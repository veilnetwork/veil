//! Complete owned-work codec cost, before encryption consumes any nonce.
//! This excludes QUIC/TCP/IP/ACK and obfs4 padding. It is not link capacity.
use crate::datagram_flows::SessionDatagramTx;
use veil_types::local_lossy_work::WorkCostKey;

pub(super) fn key(
    tx: &SessionDatagramTx,
    carrier: u64,
    ceiling: usize,
    ordered: bool,
) -> WorkCostKey {
    WorkCostKey {
        carrier,
        ceiling,
        format: u8::from(matches!(tx, SessionDatagramTx::Flows(_))) | (u8::from(ordered) << 1),
    }
}

pub(super) fn cost(
    tx: &SessionDatagramTx,
    envelope_bytes: usize,
    ceiling: usize,
    ordered: bool,
) -> Option<usize> {
    // Existing envelope accounting includes the ordinary stream cipher. The
    // datagram codec replaces that cipher with its own per-fragment AEAD.
    let frame_len = envelope_bytes.checked_sub(veil_crypto::session_cipher::AEAD_OVERHEAD)?;
    tx.frame_wire_sizes(frame_len, ceiling)
        .ok()?
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes)?
                .checked_add(if ordered { 2 } else { 0 })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use veil_types::local_lossy_work::{LocalLossyWork, WorkAdmission};

    #[test]
    fn fragmented_work_cannot_fit_using_only_its_smaller_envelope_cost() {
        use crate::local_source_activity::LocalSourceActivity;
        let now = Instant::now();
        let source = LocalSourceActivity::default();
        source.note(now);
        source.note_pressure(now);
        let tx = SessionDatagramTx::new(&[1; 32], &[2; 32], true);
        let work = LocalLossyWork::new(vec![1000; 6]).unwrap();
        let envelope = 1322 + veil_crypto::session_cipher::AEAD_OVERHEAD;
        assert!(envelope * 6 <= crate::local_source_activity::LOSSY_SECONDARY_BYTES);
        assert!(
            cost(&tx, envelope, 1382, false).unwrap() * 6
                > crate::local_source_activity::LOSSY_SECONDARY_BYTES
        );
        assert_eq!(
            source.admit_lossy_work_planned(
                &work.cell(0).unwrap(),
                envelope,
                key(&tx, 7, 1382, false),
                now,
                |n| cost(&tx, n, 1382, false)
            ),
            WorkAdmission::Rejected
        );
        // An incorrect envelope-only admission would allow this entire frame.
        let legacy = LocalLossyWork::new(vec![1000; 6]).unwrap();
        assert_eq!(
            source.admit_lossy_work(&legacy.cell(0).unwrap(), envelope, now),
            WorkAdmission::Admitted
        );
    }

    #[test]
    fn codec_plan_matches_actual_encryption_at_fragment_boundaries() {
        for flows in [false, true] {
            for ceiling in [256, 512, 1200, 1382] {
                for ordered in [false, true] {
                    let mut tx = SessionDatagramTx::new(&[1; 32], &[2; 32], flows);
                    // Both single and multiple fragments, including one-byte tails.
                    for len in [
                        1, 195, 196, 197, 451, 452, 453, 1140, 1141, 1142, 1320, 1321, 1322, 1323,
                        1342, 1343,
                    ] {
                        let frame = vec![8; len];
                        let envelope = len + veil_crypto::session_cipher::AEAD_OVERHEAD;
                        let planned = cost(&tx, envelope, ceiling, ordered).unwrap();
                        let actual = tx.encode_frame(2, &frame, ceiling).unwrap();
                        assert_eq!(
                            planned,
                            actual
                                .iter()
                                .map(|d| d.len() + if ordered { 2 } else { 0 })
                                .sum::<usize>()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn whole_work_uses_each_real_fragment_plan_and_cannot_double_pay() {
        let now = Instant::now();
        let tx = SessionDatagramTx::new(&[1; 32], &[2; 32], true);
        let work = LocalLossyWork::new_paced(
            vec![1000, 1001, 100],
            Duration::from_millis(90),
            now + Duration::from_millis(200),
        )
        .unwrap();
        // 322 envelope bytes put the first cell exactly at the 1382-byte
        // ceiling. The next byte causes a second independently encrypted fragment.
        let overhead = 322 + veil_crypto::session_cipher::AEAD_OVERHEAD;
        let mut charges = Vec::new();
        assert_eq!(
            work.cell(0).unwrap().admit_planned_at(
                1,
                1000 + overhead,
                key(&tx, 7, 1382, false),
                now,
                |n| cost(&tx, n, 1382, false),
                |n| {
                    charges.push(n);
                    Ok(())
                }
            ),
            WorkAdmission::Admitted
        );
        assert_eq!(charges, [1382 + 1443 + 482]);
        for (index, size) in [1000, 1001, 100].into_iter().enumerate() {
            assert_eq!(
                work.cell(index).unwrap().admit_planned_at(
                    1,
                    size + overhead,
                    key(&tx, 7, 1382, false),
                    now,
                    |n| cost(&tx, n, 1382, false),
                    |_| panic!("already reserved")
                ),
                WorkAdmission::Admitted
            );
        }
        // Cost queries did not allocate a flow or use a nonce.
        assert!(cost(&tx, 0, 1382, false).is_none());
    }
}
