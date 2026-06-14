//! Multi-node simulation framework for veil network testing.
//!
//! Provides `SimNetwork` — a harness that starts N in-process `NodeRuntime`
//! instances connected by real TCP on loopback, with programmatic
//! topology control (connect / disconnect / partition) and configurable
//! simulated latency and packet loss.
//!
//! # Usage
//!
//! ```rust,ignore
//! let mut net = SimNetwork::builder.nodes(5).build.await;
//! net.connect(0, 1).await;
//! net.connect(1, 2).await;
//! // wait for route convergence …
//! net.disconnect(0, 1).await;
//! ```

pub mod events;
pub mod loss;
pub mod network;
pub mod node;
#[cfg(test)]
pub mod scenarios;

pub use events::{ScenarioConfig, SimEvent, SimSnapshot, run_scenario};
pub use network::SimNetwork;
pub use node::SimNode;
