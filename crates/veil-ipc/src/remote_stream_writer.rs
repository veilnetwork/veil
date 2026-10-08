//! Cancellation-safe reliable admission, polled alongside the IPC read loop.
//! Only endpoint-owned streams enter this queue. No relay scheduling changes.
use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::Arc,
    task::Poll,
};
use veil_proto::ipc::{IPC_STREAM_WRITE_OVERHEAD, IPC_STREAM_WRITE_WINDOW};
use veil_types::FrameBroadcaster;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route {
    pub peer: [u8; 32],
    pub wire_id: u32,
    pub app: [u8; 32],
    pub endpoint: u32,
}

struct Credit {
    remaining: u32,
    closing: bool,
    route: Route,
}
struct Job {
    id: u32,
    route: Route,
    data: Option<Vec<u8>>,
    charge: u32,
}
pub(crate) struct Completion {
    pub id: u32,
    pub route: Route,
    pub charge: u32,
    pub close: bool,
    pub sent: bool,
}
type Pending = Pin<Box<dyn Future<Output = Completion> + Send>>;
#[derive(Default)]
pub(crate) struct RemoteStreamWriter {
    queue: VecDeque<Job>,
    credits: HashMap<u32, Credit>,
    // One owned admission per stream. A waiting endpoint must not serialize
    // unrelated reliable streams through the same IPC client's read loop.
    pending: VecDeque<(u32, Pending)>,
}
impl RemoteStreamWriter {
    fn credit(&mut self, id: u32, route: Route) -> Option<&mut Credit> {
        // Includes queued closes whose ownership must remain reserved until
        // their last admitted bytes and close complete (no wire-id reuse).
        if !self.credits.contains_key(&id)
            && self.credits.len() >= veil_proto::budget::MAX_IPC_STREAMS_PER_CLIENT
        {
            return None;
        }
        let credit = self.credits.entry(id).or_insert(Credit {
            remaining: IPC_STREAM_WRITE_WINDOW,
            closing: false,
            route,
        });
        (credit.route == route && !credit.closing).then_some(credit)
    }
    pub(crate) fn data(&mut self, id: u32, route: Route, data: Vec<u8>) -> bool {
        if data.is_empty() {
            return true;
        }
        let Some(charge) = u32::try_from(data.len())
            .ok()
            .and_then(|n| n.checked_add(IPC_STREAM_WRITE_OVERHEAD))
        else {
            return false;
        };
        let Some(credit) = self.credit(id, route) else {
            return false;
        };
        if charge > credit.remaining {
            return false;
        }
        credit.remaining -= charge;
        self.queue.push_back(Job {
            id,
            route,
            data: Some(data),
            charge,
        });
        true
    }
    pub(crate) fn close(&mut self, id: u32, route: Route) -> bool {
        if self
            .credits
            .get(&id)
            .is_some_and(|c| c.route == route && c.closing)
        {
            return true;
        }
        let Some(credit) = self.credit(id, route) else {
            return false;
        };
        credit.closing = true;
        self.queue.push_back(Job {
            id,
            route,
            data: None,
            charge: 0,
        });
        true
    }
    pub(crate) fn cancel(&mut self, id: u32) {
        self.queue.retain(|job| job.id != id);
        self.credits.remove(&id);
        self.pending.retain(|(pending_id, _)| *pending_id != id);
    }
    // The owned future survives cancellation of this method by select!, so a
    // partially admitted frame is never restarted, lost or duplicated.
    pub(crate) async fn next(
        &mut self,
        broadcaster: Option<Arc<dyn FrameBroadcaster>>,
    ) -> Completion {
        let mut running: HashSet<_> = self.pending.iter().map(|(id, _)| *id).collect();
        // Scan once: retain each stream's FIFO, but let independent streams
        // enter admission. Credits cap both queued bytes and active futures.
        for _ in 0..self.queue.len() {
            let job = self.queue.pop_front().unwrap();
            if !running.insert(job.id) {
                self.queue.push_back(job);
                continue;
            }
            let id = job.id;
            let broadcaster = broadcaster.clone();
            self.pending.push_back((
                id,
                Box::pin(async move {
                    let close = job.data.is_none();
                    let sent = if let Some(b) = broadcaster {
                        match job.data {
                            Some(data) => {
                                crate::handlers::stream::send_app_data(
                                    b.as_ref(),
                                    &job.route.peer,
                                    job.route.wire_id,
                                    job.route.app,
                                    job.route.endpoint,
                                    data,
                                )
                                .await
                            }
                            None => {
                                crate::handlers::stream::send_app_close_wait(
                                    b.as_ref(),
                                    &job.route.peer,
                                    job.route.wire_id,
                                    job.route.app,
                                    job.route.endpoint,
                                )
                                .await
                            }
                        }
                    } else {
                        false
                    };
                    Completion {
                        id: job.id,
                        route: job.route,
                        charge: job.charge,
                        close,
                        sent,
                    }
                }),
            ));
        }
        // Poll every independent admission, rotating after a completion.
        // Store futures here (no spawned tasks), so select! cancellation
        // retains a partially committed write and cancel(id) drops only it.
        let result = std::future::poll_fn(|cx| {
            for _ in 0..self.pending.len() {
                let (id, mut future) = self.pending.pop_front().unwrap();
                match future.as_mut().poll(cx) {
                    Poll::Ready(result) => return Poll::Ready(result),
                    Poll::Pending => self.pending.push_back((id, future)),
                }
            }
            Poll::Pending
        })
        .await;
        if !result.sent || result.close {
            self.cancel(result.id);
        } else if let Some(credit) = self.credits.get_mut(&result.id) {
            credit.remaining = credit
                .remaining
                .saturating_add(result.charge)
                .min(IPC_STREAM_WRITE_WINDOW);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::sync::Semaphore;
    use veil_proto::{AppDataPayload, AppMsg, HEADER_SIZE, codec};

    struct Source {
        attempts: Mutex<HashMap<u32, usize>>,
        accepted: Mutex<Vec<([u8; 32], Vec<u8>)>>,
        blocked: Semaphore,
    }
    impl Source {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                attempts: Mutex::new(HashMap::new()),
                accepted: Mutex::new(Vec::new()),
                blocked: Semaphore::new(0),
            })
        }
    }
    impl FrameBroadcaster for Source {
        fn send_to(&self, _: &[u8; 32], _: u8, _: Vec<u8>) -> bool {
            panic!("reliable writes must retain backpressure")
        }
        fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {}
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            vec![[9; 32], [8; 32]]
        }
        fn send_reliable_to<'a>(
            &'a self,
            peer: &'a [u8; 32],
            bytes: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            Box::pin(async move {
                let header = codec::decode_header(&bytes).unwrap();
                assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
                let attempt = {
                    let mut attempts = self.attempts.lock().unwrap();
                    let n = attempts.entry(header.stream_id).or_default();
                    let old = *n;
                    *n += 1;
                    old
                };
                // The first segment commits; the second waits for source
                // capacity, exactly where select cancellation used to restart
                // writes and where a global pending slot blocks other streams.
                if matches!(header.stream_id, 41 | 44) && attempt > 0 {
                    self.blocked.acquire().await.unwrap().forget();
                }
                self.accepted.lock().unwrap().push((*peer, bytes));
                true
            })
        }
    }
    fn route(peer: u8, wire_id: u32) -> Route {
        Route {
            peer: [peer; 32],
            wire_id,
            app: [7; 32],
            endpoint: 5,
        }
    }

    #[tokio::test]
    async fn partial_write_does_not_hold_other_streams_or_peers() {
        let source = Source::new();
        let mut writer = RemoteStreamWriter::default();
        let first: Vec<u8> = (0..6000).map(|n| (n % 251) as u8).collect();
        assert!(writer.data(1, route(9, 41), first.clone()));
        assert!(futures::poll!(Box::pin(writer.next(Some(source.clone())))).is_pending());
        assert_eq!(source.accepted.lock().unwrap().len(), 1);

        assert!(writer.data(1, route(9, 41), b"tail".to_vec()));
        assert!(writer.close(1, route(9, 41)));
        assert!(writer.data(2, route(9, 42), b"same peer".to_vec()));
        assert!(writer.close(2, route(9, 42)));
        assert!(writer.data(3, route(8, 43), b"other peer".to_vec()));
        assert!(writer.close(3, route(8, 43)));

        let independent = tokio::time::timeout(std::time::Duration::from_millis(200), async {
            let mut done = Vec::new();
            for _ in 0..4 {
                let result = writer.next(Some(source.clone())).await;
                assert!(result.sent);
                done.push((result.id, result.close));
            }
            done
        })
        .await
        .expect("a partially admitted file held independent streams");
        for id in [2, 3] {
            assert_eq!(
                independent
                    .iter()
                    .filter(|(stream, _)| *stream == id)
                    .map(|(_, close)| *close)
                    .collect::<Vec<_>>(),
                vec![false, true]
            );
        }
        assert_eq!(
            source.attempts.lock().unwrap()[&41],
            2,
            "partial write restarted"
        );

        source.blocked.add_permits(3);
        for close in [false, false, true] {
            let result = writer.next(Some(source.clone())).await;
            assert_eq!((result.id, result.close, result.sent), (1, close, true));
        }
        let accepted = source.accepted.lock().unwrap();
        let file: Vec<_> = accepted
            .iter()
            .filter(|(_, bytes)| codec::decode_header(bytes).unwrap().stream_id == 41)
            .collect();
        let reconstructed: Vec<_> = file[..3]
            .iter()
            .flat_map(|(_, bytes)| {
                let h = codec::decode_header(bytes).unwrap();
                assert_eq!(h.msg_type, AppMsg::AppData as u16);
                assert!(bytes.len() + 16 <= 4096);
                AppDataPayload::decode(&bytes[HEADER_SIZE..]).unwrap().data
            })
            .collect();
        assert_eq!(reconstructed, [first, b"tail".to_vec()].concat());
        assert_eq!(
            codec::decode_header(&file[3].1).unwrap().msg_type,
            AppMsg::AppClose as u16
        );
    }

    #[tokio::test]
    async fn cancel_partial_stream_keeps_other_admission_and_allows_safe_id_reuse() {
        let source = Source::new();
        let mut writer = RemoteStreamWriter::default();
        let bytes: Vec<u8> = (0..6000).map(|n| (n % 251) as u8).collect();
        for (id, wire) in [(1, 41), (2, 44)] {
            assert!(writer.data(id, route(9, wire), bytes.clone()));
            assert!(writer.close(id, route(9, wire)));
        }
        // Cancelling the select branch leaves both partially committed writes.
        assert!(futures::poll!(Box::pin(writer.next(Some(source.clone())))).is_pending());
        assert_eq!(source.accepted.lock().unwrap().len(), 2);
        writer.cancel(1);
        assert!(writer.data(1, route(8, 45), b"new route".to_vec()));
        let new = writer.next(Some(source.clone())).await;
        assert_eq!((new.id, new.route, new.sent), (1, route(8, 45), true));
        source.blocked.add_permits(2);
        let surviving = writer.next(Some(source.clone())).await;
        assert_eq!(
            (surviving.id, surviving.close, surviving.sent),
            (2, false, true)
        );
        let closed = writer.next(Some(source.clone())).await;
        assert_eq!((closed.id, closed.close, closed.sent), (2, true, true));
        let accepted = source.accepted.lock().unwrap();
        assert_eq!(
            accepted
                .iter()
                .filter(|(_, b)| codec::decode_header(b).unwrap().stream_id == 41)
                .count(),
            1,
            "cancelled prefix resumed or a stale close escaped after id reuse"
        );
        let reconstructed: Vec<_> = accepted
            .iter()
            .filter_map(|(_, b)| {
                let h = codec::decode_header(b).unwrap();
                (h.stream_id == 44 && h.msg_type == AppMsg::AppData as u16)
                    .then(|| AppDataPayload::decode(&b[HEADER_SIZE..]).unwrap().data)
            })
            .flatten()
            .collect();
        assert_eq!(
            reconstructed, bytes,
            "cancelling one stream restarted another prefix"
        );
    }
}
