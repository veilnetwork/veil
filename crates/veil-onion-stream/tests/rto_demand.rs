//! Real driver/mux propagation of local backlog at a network DATA timeout.
use std::{io, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use veil_onion_stream::{Addr, CellSender, Config, Frame, StreamMux};

struct Sender {
    me: Addr,
    other: mpsc::Sender<(Addr, Vec<u8>)>,
    rtos: mpsc::UnboundedSender<bool>,
}

impl CellSender for Sender {
    async fn send(&self, _: Addr, cell: Vec<u8>) -> io::Result<()> {
        // Handshakes arrive; DATA is locally accepted then lost in the network.
        if matches!(Frame::decode(&cell), Some(Frame::Data { .. })) {
            return Ok(());
        }
        self.other
            .try_send((self.me, cell))
            .map_err(io::Error::other)
    }

    async fn on_stream_data_rto_with_demand(
        &self,
        _: Addr,
        _: u32,
        _: u32,
        _: u32,
        app_limited: bool,
    ) {
        self.rtos.send(app_limited).unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn driver_and_mux_report_sparse_loss_separately_from_backlogged_loss() {
    for bytes in [8, 4096] {
        let a = Addr {
            node: [1; 32],
            app: [3; 32],
        };
        let b = Addr {
            node: [2; 32],
            app: [3; 32],
        };
        let (a_tx, a_rx) = mpsc::channel(128);
        let (b_tx, b_rx) = mpsc::channel(128);
        let (rtos, mut observed) = mpsc::unbounded_channel();
        let config = Config {
            mss: 64,
            init_cwnd: 64,
            recv_window: 8192,
            init_rto_ms: 50,
            min_rto_ms: 50,
            max_rto_ms: 50,
            ..Config::default()
        };
        let mux_a = StreamMux::new(
            a.node,
            Arc::new(Sender {
                me: a,
                other: b_tx,
                rtos: rtos.clone(),
            }),
            a_rx,
            config,
        );
        let mux_b = StreamMux::new(
            b.node,
            Arc::new(Sender {
                me: b,
                other: a_tx,
                rtos,
            }),
            b_rx,
            config,
        );
        let source = mux_a.open(b);
        let (target, _) = tokio::time::timeout(Duration::from_secs(1), mux_b.accept())
            .await
            .unwrap()
            .unwrap();
        source.write_all(&vec![0x39; bytes]).await.unwrap();
        let limited = tokio::time::timeout(Duration::from_secs(1), observed.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            limited,
            bytes == 8,
            "local demand lost between engine and sender"
        );
        source.reset(0).await;
        target.reset(0).await;
    }
}
