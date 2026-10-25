//! Lifetime of an isolated local producer's fallback circuits. File-stream
//! pools keep their existing shared/grace policy; these circuits belong to one
//! media channel and must not consume relay slots after that channel closes.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tokio::task::AbortHandle;
use veil_node_runtime::{DataCircuit, NodeServices};

#[derive(Default)]
pub(super) struct ProducerCircuitOwner {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    closed: bool,
    tasks: Vec<AbortHandle>,
    circuits: Vec<Weak<ProducerCircuit>>,
}

impl ProducerCircuitOwner {
    #[cfg(test)]
    pub(super) fn tasks_for_test(&self) -> Vec<AbortHandle> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .tasks
            .clone()
    }

    pub(super) fn is_closed(&self) -> bool {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).closed
    }

    pub(super) fn track_task(&self, task: AbortHandle) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.closed {
            task.abort();
        } else {
            state.tasks.retain(|task| !task.is_finished());
            state.tasks.push(task);
        }
    }

    /// Own the candidate and its feed before the first confirmation await.
    /// A racing close retires the candidate even if its opener ran before its
    /// abort handle could be registered.
    pub(super) fn track_circuit(
        &self,
        services: NodeServices,
        circuit: Arc<DataCircuit>,
        feed: AbortHandle,
    ) -> Option<Arc<ProducerCircuit>> {
        let owned = Arc::new(ProducerCircuit {
            services,
            circuit,
            feed,
            retired: AtomicBool::new(false),
        });
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.closed {
            drop(state);
            owned.retire();
            return None;
        }
        state.circuits.retain(|circuit| circuit.strong_count() > 0);
        state.circuits.push(Arc::downgrade(&owned));
        Some(owned)
    }

    pub(super) fn close(&self) {
        let (tasks, circuits) = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.closed = true;
            (
                std::mem::take(&mut state.tasks),
                std::mem::take(&mut state.circuits)
                    .into_iter()
                    .filter_map(|circuit| circuit.upgrade())
                    .collect::<Vec<_>>(),
            )
        };
        for task in tasks {
            task.abort();
        }
        for circuit in circuits {
            circuit.retire();
        }
    }
}

/// Pool entries and in-flight selections share this guard. Failed/cancelled
/// candidates retire too, while an ordinary pool replacement cannot retire a
/// circuit still held by a sender. The registry contains only weak references.
pub(super) struct ProducerCircuit {
    services: NodeServices,
    circuit: Arc<DataCircuit>,
    feed: AbortHandle,
    retired: AtomicBool,
}

impl ProducerCircuit {
    fn retire(&self) {
        if !self.retired.swap(true, Ordering::AcqRel) {
            self.feed.abort();
            self.services.retire_data_circuit(&self.circuit);
        }
    }
}

impl Drop for ProducerCircuit {
    fn drop(&mut self) {
        self.retire();
    }
}
