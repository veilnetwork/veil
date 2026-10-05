//! Cancellation-safe reliable admission, polled alongside the IPC read loop.
//! Only endpoint-owned streams enter this queue. No relay scheduling changes.
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::Arc,
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
    pending: Option<(u32, Pending)>,
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
        if self
            .pending
            .as_ref()
            .is_some_and(|(pending_id, _)| *pending_id == id)
        {
            self.pending = None;
        }
    }
    // The owned future survives cancellation of this method by select!, so a
    // partially admitted frame is never restarted, lost or duplicated.
    pub(crate) async fn next(
        &mut self,
        broadcaster: Option<Arc<dyn FrameBroadcaster>>,
    ) -> Completion {
        if self.pending.is_none() {
            let Some(job) = self.queue.pop_front() else {
                return std::future::pending().await;
            };
            let id = job.id;
            self.pending = Some((
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
        let result = self.pending.as_mut().unwrap().1.as_mut().await;
        self.pending = None;
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
