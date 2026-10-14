//! Bounded process-local ownership of generic connections. An authenticated
//! ingress connection or installed circuit stays separate without exposing its application role.
//! Allocation is first come, within the existing connection quota. It never
//! changes relay admission, FIFO order, bandwidth or scheduling priority.

use std::time::{Duration, Instant};
use veil_anonymity::circuit_carrier::{Carrier, LocalTransitFlow};

const SOURCE_COUNT: usize = crate::local_datagram_status::LOCAL_DATAGRAM_PRIORITIES.len();
const LEGACY_IDLE: Duration = Duration::from_secs(30);

enum Owner {
    Source(usize),
    Transit(LocalTransitFlow, Carrier),
    Legacy { bucket: usize, used: Instant },
}

#[derive(Clone, Copy)]
pub(super) struct Selection {
    pub physical: usize,
    pub counter: usize,
}

pub(super) struct ChannelAssignments<const N: usize> {
    owners: [Option<Owner>; N],
}

impl<const N: usize> Default for ChannelAssignments<N> {
    fn default() -> Self {
        Self {
            owners: std::array::from_fn(|_| None),
        }
    }
}

impl<const N: usize> ChannelAssignments<N> {
    fn reap(&mut self, now: Instant) {
        // Reap BEFORE comparing allocation identities: an expired weak witness
        // cannot alias a newly allocated connection at a reused address.
        for owner in &mut self.owners {
            let expired = match owner {
                Some(Owner::Transit(key, witness)) => witness
                    .upgrade()
                    .is_none_or(|carrier| carrier.local_transit_flow() != Some(*key)),
                Some(Owner::Legacy { used, .. }) => {
                    now.saturating_duration_since(*used) >= LEGACY_IDLE
                }
                _ => false,
            };
            if expired {
                *owner = None;
            }
        }
    }

    pub fn source_physical(&self, source: usize) -> Option<usize> {
        self.owners
            .iter()
            .position(|owner| matches!(owner, Some(Owner::Source(index)) if *index == source))
    }

    pub fn source(&mut self, source: usize) -> Option<Selection> {
        if source >= SOURCE_COUNT {
            return None;
        }
        self.reap(Instant::now());
        let physical = self.source_physical(source).or_else(|| self.free(source))?;
        self.owners[physical] = Some(Owner::Source(source));
        Some(Selection {
            physical,
            counter: source,
        })
    }

    /// Opaque authenticated ingress/circuit ownership, never frame contents,
    /// chooses a distinct live connection. Legacy ingress retains neutral buckets.
    /// Saturation returns None instead of merging two live known connections.
    pub fn transit(&mut self, witness: Option<&Carrier>, bucket: usize) -> Option<Selection> {
        self.transit_at(witness, bucket, Instant::now())
    }

    fn transit_at(
        &mut self,
        witness: Option<&Carrier>,
        bucket: usize,
        now: Instant,
    ) -> Option<Selection> {
        self.reap(now);
        let flow = witness
            .and_then(|w| w.upgrade())
            .and_then(|w| w.local_transit_flow());
        let physical = if let (Some(key), Some(witness)) = (flow, witness) {
            if let Some(index) = self
                .owners
                .iter()
                .position(|o| matches!(o, Some(Owner::Transit(existing, _)) if *existing == key))
            {
                index
            } else {
                let index = self.free(bucket)?;
                self.owners[index] = Some(Owner::Transit(key, witness.clone()));
                index
            }
        } else if let Some(index) = self.owners.iter().position(
            |o| matches!(o, Some(Owner::Legacy { bucket: existing, .. }) if *existing == bucket),
        ) {
            self.owners[index] = Some(Owner::Legacy { bucket, used: now });
            index
        } else {
            let index = self.free(bucket)?;
            self.owners[index] = Some(Owner::Legacy { bucket, used: now });
            index
        };
        Some(Selection {
            physical,
            counter: SOURCE_COUNT + physical,
        })
    }

    fn free(&self, preferred: usize) -> Option<usize> {
        self.owners
            .get(preferred)
            .filter(|owner| owner.is_none())
            .map(|_| preferred)
            .or_else(|| self.owners.iter().position(Option::is_none))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use veil_anonymity::circuit_carrier::{CarrierSend, DatagramCarrier, LocalIngressFlow};

    struct Ingress {
        key: LocalIngressFlow,
        active: AtomicBool,
    }
    impl DatagramCarrier for Ingress {
        fn local_ingress_flow(&self) -> Option<LocalIngressFlow> {
            self.active.load(Ordering::Acquire).then_some(self.key)
        }
        fn try_send(
            &self,
            _: &[u8; 32],
            _: &[u8],
            _: &mut dyn FnMut(usize) -> bool,
        ) -> CarrierSend {
            panic!("selection must never send or spend a relay budget")
        }
    }
    fn ingress(parent: usize, connection: usize) -> Arc<Ingress> {
        Arc::new(Ingress {
            key: LocalIngressFlow { parent, connection },
            active: AtomicBool::new(true),
        })
    }
    fn witness(value: &Arc<Ingress>) -> Carrier {
        Arc::downgrade(&(value.clone() as Arc<dyn DatagramCarrier>))
    }

    #[test]
    fn same_route_different_connections_do_not_merge() {
        let mut pool = ChannelAssignments::<6>::default();
        let flows: Vec<_> = (0..6).map(|i| ingress(1, i)).collect();
        let chosen: Vec<_> = flows
            .iter()
            .map(|flow| pool.transit(Some(&witness(flow)), 4).unwrap().physical)
            .collect();
        assert_eq!(
            chosen
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            6
        );
        for (flow, physical) in flows.iter().zip(chosen) {
            assert_eq!(
                pool.transit(Some(&witness(flow)), 5).unwrap().physical,
                physical
            );
        }
        // No role or priority privilege lets a seventh connection bypass quota.
        assert!(pool.transit(Some(&witness(&ingress(1, 7))), 4).is_none());
        assert!(pool.source(0).is_none());
    }

    #[test]
    fn sources_and_ingress_keep_distinct_ownership_in_either_order() {
        let mut pool = ChannelAssignments::<6>::default();
        let flow = ingress(1, 1);
        let incoming = pool.transit(Some(&witness(&flow)), 0).unwrap().physical;
        let primary = pool.source(0).unwrap();
        assert_ne!(incoming, primary.physical);
        assert_eq!(primary.counter, 0);
        assert_eq!(pool.source(0).unwrap().physical, primary.physical);
        let secondary = pool.source(1).unwrap();
        assert_ne!(secondary.physical, incoming);
        assert_ne!(secondary.physical, primary.physical);
        assert_eq!(
            pool.transit(Some(&witness(&flow)), 0).unwrap().physical,
            incoming
        );
    }

    #[test]
    fn retired_witness_is_reclaimed_before_identity_reuse() {
        let mut pool = ChannelAssignments::<1>::default();
        let first = ingress(1, 1);
        pool.transit(Some(&witness(&first)), 0).unwrap();
        first.active.store(false, Ordering::Release);
        let replacement = ingress(1, 1);
        pool.transit(Some(&witness(&replacement)), 0).unwrap();
        drop(first);
        assert!(pool.transit(Some(&witness(&ingress(2, 2))), 0).is_none());
        drop(replacement);
        assert!(pool.transit(Some(&witness(&ingress(2, 2))), 0).is_some());
    }

    #[test]
    fn legacy_bucket_does_not_steal_a_live_source_and_expires_when_idle() {
        let mut pool = ChannelAssignments::<2>::default();
        let start = Instant::now();
        let source = pool.source(0).unwrap();
        let legacy = pool.transit_at(None, 0, start).unwrap();
        assert_ne!(source.physical, legacy.physical);
        assert!(pool.transit_at(None, 1, start).is_none());
        let recycled = pool.transit_at(None, 1, start + LEGACY_IDLE).unwrap();
        assert_eq!(recycled.physical, legacy.physical);
        assert_eq!(pool.source_physical(0), Some(source.physical));
    }
}
