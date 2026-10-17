//! A bounded, locally authored lossy work item. Never serialized on the network.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_CELLS: usize = 512;
pub const MAX_SEALED_BYTES: usize = 512 * 1024 + MAX_CELLS * 64;
pub const MAX_PACING_SPAN: Duration = Duration::from_millis(100);
pub const SOURCE_WORK_MAX_AGE: Duration = Duration::from_millis(200);

#[derive(Debug, Default)]
enum Decision {
    #[default]
    Pending,
    Admitted {
        owner: u64,
        overhead: usize,
        admitted_at: Instant,
        wire_bytes: usize,
    },
    Rejected,
}

#[derive(Debug)]
pub struct LocalLossyWork {
    sizes: Vec<usize>,
    sealed_bytes: usize,
    prefix_bytes: Vec<usize>,
    pacing: Option<Pacing>,
    decision: Mutex<Decision>,
}

#[derive(Debug)]
struct Pacing {
    span: Duration,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct LocalLossyCell {
    work: Arc<LocalLossyWork>,
    index: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WorkAdmission {
    Admitted,
    Wait(Instant),
    Rejected,
}

/// Process-local observation of an admitted work boundary. Reading it cannot
/// reserve credit, release a member, renew expiry or change a decision.
pub struct WorkScheduleSnapshot {
    pub index: usize,
    pub cells: usize,
    pub sealed_bytes: usize,
    pub envelope_wire_bytes: usize,
    pub span: Duration,
    pub since_admission: Duration,
    pub until_expiry: Duration,
}

impl LocalLossyWork {
    pub fn new(sizes: Vec<usize>) -> Option<Arc<Self>> {
        if sizes.is_empty() || sizes.len() > MAX_CELLS || sizes.iter().any(|n| *n < 36) {
            return None;
        }
        let sealed_bytes = sizes
            .iter()
            .try_fold(0usize, |sum, n| sum.checked_add(*n))?;
        if sealed_bytes > MAX_SEALED_BYTES {
            return None;
        }
        let mut prefix = 0;
        let prefix_bytes = sizes
            .iter()
            .map(|size| {
                let before = prefix;
                prefix += size;
                before
            })
            .collect();
        Some(Arc::new(Self {
            sizes,
            sealed_bytes,
            prefix_bytes,
            pacing: None,
            decision: Mutex::new(Decision::Pending),
        }))
    }

    /// An origin-only schedule. No cadence/deadline is sent to another node.
    /// Existing callers without this explicit ownership retain their behavior.
    pub fn new_paced(sizes: Vec<usize>, span: Duration, expires_at: Instant) -> Option<Arc<Self>> {
        let mut work = Self::new(sizes)?;
        let value = Arc::get_mut(&mut work).expect("unpublished work is unique");
        value.pacing = Some(Pacing {
            span: if value.sizes.len() == 1 {
                Duration::ZERO
            } else {
                span.min(MAX_PACING_SPAN)
            },
            expires_at,
        });
        Some(work)
    }

    pub fn cell(self: &Arc<Self>, index: usize) -> Option<LocalLossyCell> {
        (index < self.sizes.len()).then(|| LocalLossyCell {
            work: self.clone(),
            index,
        })
    }
}

impl LocalLossyCell {
    pub fn boundary_snapshot_at(&self, now: Instant) -> Option<WorkScheduleSnapshot> {
        if self.index != 0 && self.index + 1 != self.work.sizes.len() {
            return None;
        }
        let pacing = self.work.pacing.as_ref()?;
        let state = self.work.decision.lock().unwrap_or_else(|p| p.into_inner());
        let Decision::Admitted {
            admitted_at,
            wire_bytes,
            ..
        } = *state
        else {
            return None;
        };
        Some(WorkScheduleSnapshot {
            index: self.index,
            cells: self.work.sizes.len(),
            sealed_bytes: self.work.sealed_bytes,
            envelope_wire_bytes: wire_bytes,
            span: pacing.span,
            since_admission: now.saturating_duration_since(admitted_at),
            until_expiry: pacing.expires_at.saturating_duration_since(now),
        })
    }

    /// The daemon constructs every member with the same fixed envelope shape.
    /// Charge the actual first envelope overhead for EVERY cell before sending
    /// any member. A changed shape or endpoint fails closed, never earns credit.
    pub fn admit(
        &self,
        owner: u64,
        wire_bytes: usize,
        reserve: impl FnMut(usize) -> Result<(), Instant>,
    ) -> WorkAdmission {
        self.admit_at(owner, wire_bytes, Instant::now(), reserve)
    }

    pub fn admit_at(
        &self,
        owner: u64,
        wire_bytes: usize,
        now: Instant,
        mut reserve: impl FnMut(usize) -> Result<(), Instant>,
    ) -> WorkAdmission {
        let mut state = self.work.decision.lock().unwrap_or_else(|p| p.into_inner());
        if self
            .work
            .pacing
            .as_ref()
            .is_some_and(|p| now >= p.expires_at)
        {
            *state = Decision::Rejected;
            return WorkAdmission::Rejected;
        }
        let Some(overhead) = wire_bytes.checked_sub(self.work.sizes[self.index]) else {
            *state = Decision::Rejected;
            return WorkAdmission::Rejected;
        };
        match *state {
            Decision::Rejected => WorkAdmission::Rejected,
            Decision::Admitted {
                owner: bound,
                overhead: bound_overhead,
                ..
            } if owner == bound && overhead == bound_overhead => WorkAdmission::Admitted,
            Decision::Admitted { .. } => {
                *state = Decision::Rejected;
                WorkAdmission::Rejected
            }
            Decision::Pending => {
                if self.work.pacing.as_ref().is_some_and(|p| {
                    now.checked_add(p.span)
                        .is_none_or(|end| end >= p.expires_at)
                }) {
                    *state = Decision::Rejected;
                    return WorkAdmission::Rejected;
                }
                let Some(total) = overhead
                    .checked_mul(self.work.sizes.len())
                    .and_then(|n| n.checked_add(self.work.sealed_bytes))
                else {
                    *state = Decision::Rejected;
                    return WorkAdmission::Rejected;
                };
                match reserve(total) {
                    Ok(()) => {
                        *state = Decision::Admitted {
                            owner,
                            overhead,
                            admitted_at: now,
                            wire_bytes: total,
                        };
                        WorkAdmission::Admitted
                    }
                    Err(until) => WorkAdmission::Wait(until),
                }
            }
        }
    }

    /// Query release only AFTER whole-work admission. Waiting here never
    /// refunds/repeats the reservation and never changes the original expiry.
    pub fn release_at(&self, now: Instant) -> WorkAdmission {
        let Some(pacing) = &self.work.pacing else {
            return if self.rejected() {
                WorkAdmission::Rejected
            } else {
                WorkAdmission::Admitted
            };
        };
        let mut state = self.work.decision.lock().unwrap_or_else(|p| p.into_inner());
        if now >= pacing.expires_at {
            *state = Decision::Rejected;
            return WorkAdmission::Rejected;
        }
        match *state {
            Decision::Admitted {
                overhead,
                admitted_at,
                wire_bytes,
                ..
            } => {
                // Admission checked that the complete cost fits usize; every
                // prefix is smaller. Exact integer time arithmetic avoids
                // rounding a large frame's final members back to the first.
                let prefix = self.work.prefix_bytes[self.index] + self.index * overhead;
                let nanos = pacing.span.as_nanos() * prefix as u128 / wire_bytes as u128;
                let due = admitted_at + Duration::from_nanos(nanos as u64);
                if now < due {
                    WorkAdmission::Wait(due)
                } else {
                    WorkAdmission::Admitted
                }
            }
            _ => WorkAdmission::Rejected,
        }
    }

    /// Original daemon receipt deadline, shared by every member and retry.
    pub fn expires_at(&self) -> Option<Instant> {
        self.work.pacing.as_ref().map(|p| p.expires_at)
    }

    pub fn reject(&self) {
        *self.work.decision.lock().unwrap_or_else(|p| p.into_inner()) = Decision::Rejected;
    }

    pub fn rejected(&self) -> bool {
        self.work
            .pacing
            .as_ref()
            .is_some_and(|p| Instant::now() >= p.expires_at)
            || matches!(
                *self.work.decision.lock().unwrap_or_else(|p| p.into_inner()),
                Decision::Rejected
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paced_members_reserve_the_whole_wire_cost_once_and_keep_release_times() {
        let now = Instant::now();
        let span = Duration::from_millis(90);
        let work = LocalLossyWork::new_paced(vec![1000, 800, 400], span, now + SOURCE_WORK_MAX_AGE)
            .unwrap();
        let first = work.cell(0).unwrap();
        assert_eq!(
            first.admit_at(7, 1316, now, |n| {
                assert_eq!(n, 3148);
                Ok(())
            }),
            WorkAdmission::Admitted
        );
        let snapshot = first.boundary_snapshot_at(now).unwrap();
        assert_eq!(
            (
                snapshot.index,
                snapshot.cells,
                snapshot.sealed_bytes,
                snapshot.envelope_wire_bytes
            ),
            (0, 3, 2200, 3148)
        );
        assert_eq!(
            (
                snapshot.span,
                snapshot.since_admission,
                snapshot.until_expiry
            ),
            (span, Duration::ZERO, SOURCE_WORK_MAX_AGE)
        );
        // Even a future/expired observation cannot alter credit or expiry.
        assert_eq!(
            first
                .boundary_snapshot_at(now + SOURCE_WORK_MAX_AGE)
                .unwrap()
                .until_expiry,
            Duration::ZERO
        );
        assert_eq!(first.release_at(now), WorkAdmission::Admitted);
        let second = work.cell(1).unwrap();
        assert!(second.boundary_snapshot_at(now).is_none());
        let due = now + Duration::from_nanos((span.as_nanos() * 1316 / 3148) as u64);
        assert_eq!(
            second.admit_at(7, 1116, now, |_| panic!("already reserved")),
            WorkAdmission::Admitted
        );
        assert_eq!(second.release_at(now), WorkAdmission::Wait(due));
        assert_eq!(
            second.release_at(due - Duration::from_nanos(1)),
            WorkAdmission::Wait(due)
        );
        assert_eq!(second.release_at(due), WorkAdmission::Admitted);
        assert_eq!(
            second.admit_at(7, 1116, due, |_| panic!("retry cannot renew credit")),
            WorkAdmission::Admitted
        );
        let last = work.cell(2).unwrap();
        let last_due = now + Duration::from_nanos((span.as_nanos() * 2432 / 3148) as u64);
        assert_eq!(last.release_at(due), WorkAdmission::Wait(last_due));
        assert_eq!(last.release_at(last_due), WorkAdmission::Admitted);
    }

    #[test]
    fn a_schedule_that_cannot_finish_is_rejected_before_spending_credit() {
        let now = Instant::now();
        let work =
            LocalLossyWork::new_paced(vec![1000; 3], MAX_PACING_SPAN, now + SOURCE_WORK_MAX_AGE)
                .unwrap();
        assert_eq!(
            work.cell(0)
                .unwrap()
                .admit_at(1, 1316, now + Duration::from_millis(150), |_| panic!(
                    "expired schedule"
                )),
            WorkAdmission::Rejected
        );
        assert!(work.cell(2).unwrap().rejected());
    }

    #[test]
    fn paced_expiry_and_rejection_cannot_be_revived_by_later_members() {
        let now = Instant::now();
        let end = now + SOURCE_WORK_MAX_AGE;
        let work = LocalLossyWork::new_paced(vec![1000; 3], MAX_PACING_SPAN, end).unwrap();
        assert_eq!(
            work.cell(0).unwrap().admit_at(1, 1316, now, |_| Ok(())),
            WorkAdmission::Admitted
        );
        assert_eq!(
            work.cell(2).unwrap().release_at(end),
            WorkAdmission::Rejected
        );
        assert_eq!(
            work.cell(1)
                .unwrap()
                .admit_at(1, 1316, now, |_| panic!("rejected work")),
            WorkAdmission::Rejected
        );
        let single = LocalLossyWork::new_paced(vec![1000], MAX_PACING_SPAN, end).unwrap();
        let at = end - Duration::from_millis(1);
        assert_eq!(
            single.cell(0).unwrap().admit_at(1, 1316, at, |_| Ok(())),
            WorkAdmission::Admitted
        );
        assert_eq!(
            single.cell(0).unwrap().release_at(at),
            WorkAdmission::Admitted
        );
    }

    #[test]
    fn all_cells_reserve_once_including_envelope_overhead_and_retries() {
        let work = LocalLossyWork::new(vec![1000, 800, 400]).unwrap();
        let first = work.cell(0).unwrap();
        let mut charges = Vec::new();
        assert_eq!(
            first.admit(7, 1316, |n| {
                charges.push(n);
                Ok(())
            }),
            WorkAdmission::Admitted
        );
        assert_eq!(charges, [3148]);
        for cell in [first, work.cell(1).unwrap(), work.cell(2).unwrap()] {
            let bytes = work.sizes[cell.index] + 316;
            assert_eq!(
                cell.admit(7, bytes, |_| panic!("already reserved")),
                WorkAdmission::Admitted
            );
        }
    }

    #[test]
    fn failed_datagram_decision_cannot_admit_a_tail_in_a_later_window() {
        let work = LocalLossyWork::new(vec![1000; 3]).unwrap();
        let first = work.cell(0).unwrap();
        let until = Instant::now();
        assert_eq!(
            first.admit(1, 1316, |_| Err(until)),
            WorkAdmission::Wait(until)
        );
        first.reject();
        assert_eq!(
            work.cell(2).unwrap().admit(1, 1316, |_| panic!("rejected")),
            WorkAdmission::Rejected
        );
    }

    #[test]
    fn ordered_wait_retries_the_whole_cost_without_granting_partial_credit() {
        let work = LocalLossyWork::new(vec![1000, 800]).unwrap();
        let first = work.cell(0).unwrap();
        let until = Instant::now();
        assert_eq!(
            first.admit(1, 1316, |n| {
                assert_eq!(n, 2432);
                Err(until)
            }),
            WorkAdmission::Wait(until)
        );
        assert_eq!(
            first.admit(1, 1316, |n| {
                assert_eq!(n, 2432);
                Ok(())
            }),
            WorkAdmission::Admitted
        );
    }

    #[test]
    fn another_endpoint_or_changed_envelope_cannot_reuse_a_reservation() {
        for (owner, bytes) in [(2, 1316), (1, 1317)] {
            let work = LocalLossyWork::new(vec![1000; 2]).unwrap();
            assert_eq!(
                work.cell(0).unwrap().admit(1, 1316, |_| Ok(())),
                WorkAdmission::Admitted
            );
            assert_eq!(
                work.cell(1)
                    .unwrap()
                    .admit(owner, bytes, |_| panic!("no new credit")),
                WorkAdmission::Rejected
            );
        }
    }

    #[test]
    fn bounds_cover_supported_frames_and_reject_unbounded_descriptors() {
        assert!(LocalLossyWork::new(vec![1024 + 36; 512]).is_some());
        for sizes in [
            vec![],
            vec![35],
            vec![36; 513],
            vec![usize::MAX, 36],
            vec![MAX_SEALED_BYTES + 1],
        ] {
            assert!(LocalLossyWork::new(sizes).is_none());
        }
    }
}
