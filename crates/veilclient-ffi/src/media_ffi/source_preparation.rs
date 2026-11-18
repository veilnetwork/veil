//! Source preparation during media open, before the host starts capture.
//! The node receives only an owned LOCAL request; no dummy RTP or wire role.
use super::*;
use tokio::time::Instant;
use veil_types::LocalDatagramChannelState as State;

const LANES: [u8; 5] = [
    veil_proto::priority::REALTIME,
    veil_proto::priority::BULK,
    veil_proto::priority::BACKGROUND,
    veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
    veil_proto::ipc::LOCAL_SIGNALING_LANE,
];
const MEDIA_LANES: usize = 3;
const POLL_STEP: std::time::Duration = std::time::Duration::from_millis(100);
const PRIMARY_RECHECK: std::time::Duration = std::time::Duration::from_millis(500);

fn preparation_ready(index: usize, state: Option<State>) -> bool {
    match index {
        0 => state == Some(State::Ready),
        1..MEDIA_LANES => matches!(state, Some(State::Ready | State::Unsupported)),
        // DATA and signaling can finish warming in the background once accepted.
        _ => state.is_some(),
    }
}

async fn prepare_sources<Q, F>(mut query: Q, budget: std::time::Duration) -> bool
where
    Q: FnMut(u8, bool) -> F,
    F: std::future::Future<Output = Result<Option<State>, ClientError>>,
{
    let started = Instant::now();
    let mut states = [None; LANES.len()];
    let result = tokio::time::timeout(budget, async {
        let mut begun = [false; LANES.len()];
        let mut last_primary_check: Option<Instant> = None;
        loop {
            let mut quota_limited = false;
            let mut deferred: [bool; LANES.len()] =
                std::array::from_fn(|index| preparation_ready(index, states[index]));
            // Check primary periodically while other lanes warm, so losing
            // its support can still end the attempt before the deadline.
            let periodic_primary_check =
                deferred[0] && last_primary_check.is_some_and(|at| at.elapsed() >= PRIMARY_RECHECK);
            deferred[0] &= !periodic_primary_check;
            for validating in [false, true] {
                for (index, lane) in LANES.iter().enumerate() {
                    // Poll unresolved lanes first. Confirm deferred media
                    // snapshots only when the other lanes are ready; cached
                    // readiness cannot survive a retirement or rekey unchecked.
                    if deferred[index] != validating || (validating && index >= MEDIA_LANES) {
                        continue;
                    }
                    states[index] = match query(*lane, !begun[index]).await {
                        Ok(state) => state,
                        Err(_) => return false,
                    };
                    begun[index] |= states[index].is_some();
                    quota_limited |= states[index].is_none();
                    if index == 0 {
                        if states[0] == Some(State::Unsupported) {
                            // Legacy daemon/link: preserve the established open path.
                            return false;
                        }
                        last_primary_check = Some(Instant::now());
                    }
                }
                if !states
                    .iter()
                    .enumerate()
                    .all(|(i, &s)| preparation_ready(i, s))
                {
                    break;
                }
                if validating {
                    return true;
                }
            }
            // Share the existing 10-query/s bucket instead of starving a
            // later plane by repeatedly polling the first one at the cap.
            let delay = if quota_limited {
                std::time::Duration::from_millis(350)
            } else if periodic_primary_check {
                // Let the bucket replenish the extra primary query as well
                // as the ordinary poll. Otherwise the watchdog itself can
                // drain a low bucket just before the last lane becomes ready.
                POLL_STEP * 2
            } else {
                POLL_STEP
            };
            tokio::time::sleep(delay).await;
        }
    })
    .await;
    if veil_session::rt_trace::rt_trace_enabled() {
        log::info!(
            "media.source_prepare ready={} deadline_reached={} elapsed_ms={} primary={:?} video={:?} screen={:?} data={:?} signaling={:?}",
            matches!(result, Ok(true)),
            result.is_err(),
            started.elapsed().as_millis(),
            states[0],
            states[1],
            states[2],
            states[3],
            states[4],
        );
    }
    result.unwrap_or(false)
}

pub(super) fn prepare_app_sources(app: &VeilApp, peer: [u8; 32], relayed: bool) -> bool {
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
    ready
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

    #[tokio::test(start_paused = true)]
    async fn warming_screen_lane_does_not_exhaust_the_local_query_budget() {
        // Same initial burst and refill rate as the IPC query bucket. Only
        // screen sharing is still warming; the other lanes can already send.
        for (initial_tokens, warm_ms, expected_ms) in [(30.0, 2650, 2700), (8.0, 2800, 2800)] {
            let started = tokio::time::Instant::now();
            let mut last = started;
            let mut tokens = initial_tokens;
            let mut denied = 0;
            let mut primary_queries = Vec::new();
            let mut video_queries = 0;
            let ready = prepare_sources(
                |lane, _| {
                    let now = tokio::time::Instant::now();
                    tokens = (tokens + now.duration_since(last).as_secs_f64() * 10.0).min(30.0);
                    last = now;
                    let state = if tokens < 1.0 {
                        denied += 1;
                        None
                    } else {
                        tokens -= 1.0;
                        if lane == veil_proto::priority::REALTIME {
                            primary_queries.push(now);
                        }
                        if lane == veil_proto::priority::BULK {
                            video_queries += 1;
                        }
                        Some(
                            if lane == veil_proto::priority::BACKGROUND
                                && now.duration_since(started)
                                    < std::time::Duration::from_millis(warm_ms)
                            {
                                State::Warming
                            } else {
                                State::Ready
                            },
                        )
                    };
                    std::future::ready(Ok(state))
                },
                std::time::Duration::from_secs(3),
            )
            .await;
            assert!(
                ready,
                "the screen lane became ready with {initial_tokens} initial tokens"
            );
            assert_eq!(started.elapsed().as_millis(), expected_ms);
            assert_eq!(denied, 0);
            assert_eq!(
                primary_queries.len(),
                7,
                "bounded checks plus final recheck"
            );
            assert_eq!(primary_queries.last(), Some(&tokio::time::Instant::now()));
            assert_eq!(video_queries, 2, "initial preparation and final recheck");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn primary_support_loss_is_observed_while_other_lanes_warm() {
        let started = Instant::now();
        let ready = prepare_sources(
            |lane, _| {
                let state = match lane {
                    veil_proto::priority::REALTIME if started.elapsed() >= PRIMARY_RECHECK => {
                        State::Unsupported
                    }
                    veil_proto::priority::BACKGROUND => State::Warming,
                    _ => State::Ready,
                };
                std::future::ready(Ok(Some(state)))
            },
            std::time::Duration::from_secs(3),
        )
        .await;
        assert!(!ready);
        assert_eq!(started.elapsed(), PRIMARY_RECHECK);
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
