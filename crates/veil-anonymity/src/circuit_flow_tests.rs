use super::*;
use crate::{
    circuit_carrier::{CarrierSend, DatagramCarrier},
    circuit_data::CircuitCellBytes,
    circuit_setup::CircuitInstall,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn install(table: &CircuitTable, cid: u32) -> Arc<CircuitState> {
    table
        .install(
            &CircuitInstall {
                circuit_id_in: cid,
                circuit_id_out: cid + 100,
                circuit_key: [4; 32],
                cell_bytes: CircuitCellBytes::legacy(),
            },
            [1; 32],
            Some([2; 32]),
            1000,
        )
        .unwrap()
}

struct ReturnPipe(AtomicUsize);
impl DatagramCarrier for ReturnPipe {
    fn try_send(
        &self,
        _: &[u8; 32],
        frame: &[u8],
        admit: &mut dyn FnMut(usize) -> bool,
    ) -> CarrierSend {
        self.0.fetch_add(1, Ordering::Relaxed);
        if admit(42) {
            if frame == b"partial" {
                CarrierSend::Dropped { wire_bytes: 17 }
            } else {
                CarrierSend::Sent { wire_bytes: 42 }
            }
        } else {
            CarrierSend::Dropped { wire_bytes: 0 }
        }
    }
}

#[test]
fn circuit_flow_is_stable_before_return_observation_and_distinct_by_direction_and_incarnation() {
    let table = CircuitTable::new();
    let state = install(&table, 10);
    let forward = state.outbound_carrier(true).upgrade().unwrap();
    let backward = state.outbound_carrier(false).upgrade().unwrap();
    let key = forward.local_transit_flow().unwrap();
    assert!(forward.local_ingress_flow().is_none());
    assert_ne!(key, backward.local_transit_flow().unwrap());
    let pipe: Arc<dyn DatagramCarrier> = Arc::new(ReturnPipe(AtomicUsize::new(0)));
    let weak = Arc::downgrade(&pipe);
    state.observe_carrier(false, 3, Some(&weak));
    state.observe_carrier(false, 2, None);
    assert!(state.destination_carrier(true).is_some());
    assert_eq!(forward.local_transit_flow(), Some(key));
    state.observe_carrier(false, 4, None);
    assert!(state.destination_carrier(true).is_none());
    assert_eq!(forward.local_transit_flow(), Some(key));
    table.remove(&[1; 32], 10);
    assert!(forward.local_transit_flow().is_none());
    assert!(backward.local_transit_flow().is_none());
    // Even retaining both state and carrier cannot revive retired ownership.
    state.observe_carrier(false, 5, Some(&weak));
    assert!(forward.local_transit_flow().is_none());
    let replacement = install(&table, 10);
    assert_ne!(
        replacement
            .outbound_carrier(true)
            .upgrade()
            .unwrap()
            .local_transit_flow(),
        Some(key)
    );
}

#[test]
fn fallback_preserves_peer_binding_admission_and_exact_partial_result() {
    let table = CircuitTable::new();
    let state = install(&table, 10);
    let forward = state.outbound_carrier(true).upgrade().unwrap();
    let pipe = Arc::new(ReturnPipe(AtomicUsize::new(0)));
    let erased: Arc<dyn DatagramCarrier> = pipe.clone();
    let weak = Arc::downgrade(&erased);
    let mut spent = 0;
    let mut admit = |n| {
        spent += n;
        true
    };
    assert!(matches!(
        forward.try_send(&[2; 32], &[], &mut admit),
        CarrierSend::Unavailable
    ));
    state.observe_carrier(false, 1, Some(&weak));
    assert!(matches!(
        forward.try_send(&[1; 32], &[], &mut admit),
        CarrierSend::Unavailable
    ));
    assert_eq!(pipe.0.load(Ordering::Relaxed), 0);
    assert!(matches!(
        forward.try_send(&[2; 32], &[], &mut admit),
        CarrierSend::Sent { wire_bytes: 42 }
    ));
    assert!(matches!(
        forward.try_send(&[2; 32], b"partial", &mut admit),
        CarrierSend::Dropped { wire_bytes: 17 }
    ));
    assert!(matches!(
        forward.try_send(&[2; 32], &[], &mut |_| false),
        CarrierSend::Dropped { wire_bytes: 0 }
    ));
    table.remove(&[1; 32], 10);
    assert!(matches!(
        forward.try_send(&[2; 32], &[], &mut admit),
        CarrierSend::Unavailable
    ));
    assert_eq!(pipe.0.load(Ordering::Relaxed), 3);
    assert_eq!(spent, 84);
}

#[test]
fn gc_and_table_drop_retire_witnesses_despite_retained_state() {
    let table = CircuitTable::with_params(10, 10, 5);
    let state = install(&table, 10);
    let carrier = state.outbound_carrier(true).upgrade().unwrap();
    assert_eq!(table.gc(1005), 1);
    assert!(carrier.local_transit_flow().is_none());
    let state = install(&table, 10);
    let carrier = state.outbound_carrier(true).upgrade().unwrap();
    drop(table);
    assert!(carrier.local_transit_flow().is_none());
    assert!(
        state
            .outbound_carrier(false)
            .upgrade()
            .unwrap()
            .local_transit_flow()
            .is_none()
    );
}

#[test]
fn queued_weak_witness_does_not_keep_circuit_ownership_alive() {
    let table = CircuitTable::new();
    let state = install(&table, 10);
    let weak = state.outbound_carrier(true);
    table.remove(&[1; 32], 10);
    drop(state);
    assert!(weak.upgrade().is_none());
}
