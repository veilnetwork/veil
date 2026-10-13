//! A bounded, locally authored lossy work item. Never serialized on the network.
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const MAX_CELLS: usize = 512;
pub const MAX_SEALED_BYTES: usize = 512 * 1024 + MAX_CELLS * 64;

#[derive(Debug, Default)]
enum Decision {
    #[default]
    Pending,
    Admitted {
        owner: u64,
        overhead: usize,
    },
    Rejected,
}

#[derive(Debug)]
pub struct LocalLossyWork {
    sizes: Vec<usize>,
    sealed_bytes: usize,
    decision: Mutex<Decision>,
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
        Some(Arc::new(Self {
            sizes,
            sealed_bytes,
            decision: Mutex::new(Decision::Pending),
        }))
    }

    pub fn cell(self: &Arc<Self>, index: usize) -> Option<LocalLossyCell> {
        (index < self.sizes.len()).then(|| LocalLossyCell {
            work: self.clone(),
            index,
        })
    }
}

impl LocalLossyCell {
    /// The daemon constructs every member with the same fixed envelope shape.
    /// Charge the actual first envelope overhead for EVERY cell before sending
    /// any member. A changed shape or endpoint fails closed, never earns credit.
    pub fn admit(
        &self,
        owner: u64,
        wire_bytes: usize,
        mut reserve: impl FnMut(usize) -> Result<(), Instant>,
    ) -> WorkAdmission {
        let mut state = self.work.decision.lock().unwrap_or_else(|p| p.into_inner());
        let Some(overhead) = wire_bytes.checked_sub(self.work.sizes[self.index]) else {
            *state = Decision::Rejected;
            return WorkAdmission::Rejected;
        };
        match *state {
            Decision::Rejected => WorkAdmission::Rejected,
            Decision::Admitted {
                owner: bound,
                overhead: bound_overhead,
            } if owner == bound && overhead == bound_overhead => WorkAdmission::Admitted,
            Decision::Admitted { .. } => {
                *state = Decision::Rejected;
                WorkAdmission::Rejected
            }
            Decision::Pending => {
                let Some(total) = overhead
                    .checked_mul(self.work.sizes.len())
                    .and_then(|n| n.checked_add(self.work.sealed_bytes))
                else {
                    *state = Decision::Rejected;
                    return WorkAdmission::Rejected;
                };
                match reserve(total) {
                    Ok(()) => {
                        *state = Decision::Admitted { owner, overhead };
                        WorkAdmission::Admitted
                    }
                    Err(until) => WorkAdmission::Wait(until),
                }
            }
        }
    }

    pub fn reject(&self) {
        *self.work.decision.lock().unwrap_or_else(|p| p.into_inner()) = Decision::Rejected;
    }

    pub fn rejected(&self) -> bool {
        matches!(
            *self.work.decision.lock().unwrap_or_else(|p| p.into_inner()),
            Decision::Rejected
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
