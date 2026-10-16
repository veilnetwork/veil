//! Source preparation during media open, before the host starts capture.
//! The node receives only an owned LOCAL request; no dummy RTP or wire role.
use super::*;
use veil_types::LocalDatagramChannelState as State;

const LANES: [u8; 5] = [
    veil_proto::priority::REALTIME,
    veil_proto::priority::BULK,
    veil_proto::priority::BACKGROUND,
    veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
    veil_proto::ipc::LOCAL_SIGNALING_LANE,
];

async fn prepare_sources<Q, F>(mut query: Q, budget: std::time::Duration) -> bool
where
    Q: FnMut(u8, bool) -> F,
    F: std::future::Future<Output = Result<Option<State>, ClientError>>,
{
    tokio::time::timeout(budget, async {
        let mut states = [None; LANES.len()];
        let mut begun = [false; LANES.len()];
        loop {
            let mut quota_limited = false;
            for (index, lane) in LANES.iter().enumerate() {
                // DATA/control can continue preparing in the background.
                // Refresh every media snapshot instead of reusing a Ready
                // value across a quota retry, parent retirement or rekey.
                if index >= 3 && states[index].is_some() {
                    continue;
                }
                states[index] = match query(*lane, !begun[index]).await {
                    Ok(state) => state,
                    Err(_) => return false,
                };
                begun[index] |= states[index].is_some();
                quota_limited |= states[index].is_none();
                if index == 0 && states[index] == Some(State::Unsupported) {
                    // Legacy daemon/link: preserve the established open path.
                    return false;
                }
            }
            if states[0] == Some(State::Ready)
                && states[1..3]
                    .iter()
                    .all(|s| matches!(s, Some(State::Ready | State::Unsupported)))
                && states[3..].iter().all(Option::is_some)
            {
                return true;
            }
            // Share the existing 10-query/s bucket instead of starving a
            // later plane by repeatedly polling the first one at the cap.
            tokio::time::sleep(std::time::Duration::from_millis(if quota_limited {
                350
            } else {
                100
            }))
            .await;
        }
    })
    .await
    .unwrap_or(false)
}

pub(super) fn prepare_app_sources(app: &VeilApp, peer: [u8; 32], relayed: bool) {
    // ffi_prelude has already rejected Tokio-worker reentry. Hosts execute
    // these existing blocking open functions on their SDK worker.
    let started = std::time::Instant::now();
    let ready = app.bundle.runtime.block_on(prepare_sources(
        |lane, refresh| async move {
            let client = app.bundle.client.lock().await;
            if refresh {
                client
                    .prepare_local_datagram_channel(app.app_id, peer, lane, relayed)
                    .await
            } else {
                client
                    .local_datagram_channel_state(app.app_id, peer, lane, relayed)
                    .await
            }
        },
        std::time::Duration::from_secs(3),
    ));
    media::diag(format_args!(
        "source preparation relayed={relayed} ready={ready} elapsed_ms={}",
        started.elapsed().as_millis()
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn legacy_is_immediate_and_does_not_request_more_sources() {
        let mut calls = 0;
        assert!(
            !prepare_sources(
                |_, _| {
                    calls += 1;
                    std::future::ready(Ok(Some(State::Unsupported)))
                },
                std::time::Duration::from_secs(3)
            )
            .await
        );
        assert_eq!(calls, 1);
    }

    #[tokio::test]
    async fn waits_for_media_while_other_sources_prepare_once_in_background() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let ready = prepare_sources(
            |lane, refresh| {
                let mut seen = calls.lock().unwrap();
                let prior = seen.iter().filter(|&&(l, _)| l == lane).count();
                assert_eq!(refresh, prior == 0, "polling must not restart preparation");
                seen.push((lane, refresh));
                std::future::ready(Ok(Some(if prior == 0 {
                    State::Warming
                } else {
                    State::Ready
                })))
            },
            std::time::Duration::from_secs(2),
        )
        .await;
        assert!(ready);
        let seen = calls.lock().unwrap();
        for lane in LANES[..3].iter() {
            assert_eq!(seen.iter().filter(|(l, _)| l == lane).count(), 2);
        }
        for lane in LANES[3..].iter() {
            assert_eq!(seen.iter().filter(|(l, _)| l == lane).count(), 1);
        }
    }

    #[tokio::test]
    async fn quota_retry_cannot_reuse_stale_primary_readiness() {
        let mut counts = [0; 7];
        assert!(
            prepare_sources(
                |lane, _| {
                    counts[usize::from(lane)] += 1;
                    let n = counts[usize::from(lane)];
                    std::future::ready(Ok(match (lane, n) {
                        (0, 2) => Some(State::Warming),
                        (veil_proto::priority::BULK, 1) => None,
                        _ => Some(State::Ready),
                    }))
                },
                std::time::Duration::from_secs(2)
            )
            .await
        );
        assert_eq!(counts[0], 3);
    }

    #[tokio::test]
    async fn unready_or_wedged_queries_have_one_total_deadline() {
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            prepare_sources(
                |_, _| std::future::pending::<Result<Option<State>, ClientError>>(),
                std::time::Duration::from_millis(20),
            ),
        )
        .await
        .unwrap();
        assert!(!result);
    }
}
