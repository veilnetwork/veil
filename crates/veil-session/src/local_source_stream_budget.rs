//! Bound this endpoint's write-ahead on the ordered compatibility path.
//! Transit keeps its existing WRR/FIFO and normal batch/queue capacity.

pub(super) const ACTIVE_SOURCE_WIRE_BYTES: usize = 4096;

pub(super) fn fits(
    primary_active: bool,
    local_priority: u8,
    pending_blobs: usize,
    batch_bytes: usize,
    next_bytes: usize,
    batch_has_local_source: bool,
) -> bool {
    use veil_proto::priority::{BULK, INTERACTIVE};
    if !primary_active {
        return true;
    }
    // Only local bulk/background waits for the previous blob to drain.
    // Primary write-ahead is checked separately by the caller. This byte
    // budget does not add a pending-blob restriction to primary/control.
    if local_priority >= BULK && local_priority != crate::LOCAL_SIGNALING_LANE && pending_blobs != 0
    {
        return false;
    }
    // Keep whole frames live even when a single frame exceeds the budget.
    if batch_bytes == 0 {
        return true;
    }
    if local_priority == INTERACTIVE && !batch_has_local_source {
        return true;
    }
    batch_bytes
        .checked_add(next_bytes)
        .is_some_and(|sum| super::padded_wire_len(sum) <= ACTIVE_SOURCE_WIRE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::priority::{BACKGROUND, BULK, INTERACTIVE, REALTIME};

    #[test]
    fn source_bulk_cannot_fill_the_post_priority_fifo_during_primary_activity() {
        assert!(fits(false, BACKGROUND, 7, 0, 60_000, false));
        assert!(!fits(true, BACKGROUND, 1, 0, 2000, false));
        assert!(!fits(true, BULK, 1, 200, 2000, true));
        assert!(fits(true, REALTIME, 1, 0, 200, false));
    }

    #[test]
    fn active_source_batch_ends_before_a_whole_frame_crosses_the_wire_budget() {
        assert!(fits(true, BACKGROUND, 0, 1000, 1000, true));
        assert!(!fits(true, BACKGROUND, 0, 3000, 2000, true));
        assert!(!fits(true, REALTIME, 0, 3000, 2000, true));
        assert!(fits(true, BACKGROUND, 0, 0, 60_000, false));
        assert!(!fits(true, INTERACTIVE, 0, 3000, 2000, true));
    }

    #[test]
    fn neutral_transit_keeps_ordinary_capacity_and_batching() {
        assert!(fits(true, INTERACTIVE, 7, 0, 60_000, false));
        assert!(fits(true, INTERACTIVE, 7, 20_000, 20_000, false));
    }
}
