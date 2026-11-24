# P-Net rollout plan

P-Net should converge after a peer joins, disconnects, or loses admission.
The network owner authorizes membership and policy. Keep existing OVL1
sessions, IPC clients, and messenger traffic compatible throughout rollout.

## 1. Reconcile configured routes

- Reconcile ogate routes against the daemon's existing P-Net status query.
  Keep the full configured peer list so a late peer can gain a route.
- Require a verified live session for a private route. Enforce certificate
  expiry on the packet path and remove a peer's route on a query timeout.
- Pace and group requests within the existing daemon quota. Exercise late
  admission and loss of session over local IPC with a list larger than the
  daemon's burst allowance. Verify that
  plain open mode and authorized source-IP checks retain their behavior.

## 2. Qualify mixed versions and load

- Run a private stand with the current daemon and the previous release.
  Exercise late join, disconnect, expiry, a banned peer, and daemon recovery.
- Run public chat delivery on the same stand. Compare control-plane CPU,
  query rates, route convergence, throughput, and p95/p99 packet latency
  as the peer list grows. Include a slow daemon and a busy data path.
  Measure the time to remove a route as well as the time to add it.
- Use the results to decide whether the daemon needs an optional local
  admission-change subscription. Keep the existing status query available
  to earlier IPC clients.

## 3. Distribute owner-authorized peer policy

- Specify a signed policy for membership and virtual address allocations.
  Bind it to the network ID and owner, persist the newest accepted revision,
  and define behavior for expired policy, replay, conflicting addresses,
  and a disconnected node rejoining the network.
- Stage adoption in parallel with locally configured peers. Define migration,
  revocation and owner-key rotation before deploying automatic policy
  updates. Keep private traffic gated on verified membership throughout.
