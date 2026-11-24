# P-Net rollout plan

P-Net should converge after a peer joins, disconnects, or loses admission.
The network owner authorizes membership and policy. Keep existing OVL1
sessions, IPC clients, and messenger traffic compatible throughout rollout.

## 1. Reconcile configured routes

- Reconcile ogate routes against the daemon's existing P-Net status query.
  Keep the full configured peer list so a late peer can gain a route.
- Require a verified live session for a private route. Enforce certificate
  expiry on the packet path and remove a peer's route on a query timeout.
  Treat a banned peer as denied even if its transport is still open.
- Pace and group requests within the existing daemon quota. Exercise late
  admission and loss of session over local IPC with a list larger than the
  daemon's burst allowance. Verify that
  plain open mode and authorized source-IP checks retain their behavior.

## 2. Qualify mixed versions and load

- Run a private stand with the current daemon and the previous release.
  Exercise late join, disconnect, expiry, a banned peer, and daemon recovery.
- Review private-node discovery on the stand. Default meeting points
  can contact public rendezvous relays even in private mode. Exercise
  both isolated and explicitly configured discovery before changing defaults.
- Run public chat delivery on the same stand. Compare control-plane CPU,
  query rates, route convergence, throughput, and p95/p99 packet latency
  as the peer list grows. Include a slow daemon and a busy data path.
  Measure the time to remove a route as well as the time to add it.
- Use the results to decide whether the daemon needs an optional local
  admission-change subscription. Keep the existing status query available
  to earlier IPC clients.
- At the legacy query pace, 1,024 configured peers take about 128 s to
  sweep. Negotiated IPC groups use the same admission checks with a
  per-connection request quota and a daemon-wide lookup budget. Extend
  qualification to many simultaneous live sessions and a slow daemon.

### Qualification results

- A loopback stand paired Veil v0.11.59 (`6625b9ea`) with the current
  daemon. A late peer with the correct membership was admitted, a peer
  with a wrong-network certificate was rejected after disconnecting, and
  the pair resumed after upgrading the old daemon and restarting the
  other one. A ban removed admission while certificate metadata remained
  readable. The stand used static peers with external discovery disabled.
- The public configuration of the same version pair admitted peers
  without private certificates. The Veil SDK chat sample delivered at
  least 1,000 messages in each direction.
- Two isolated Linux ARM64 containers passed traffic through real TUN
  interfaces. In one run the tunnel resumed 1.34 s after the daemon
  restart, using the same ogate process and TUN interface. Tunnel traffic
  stopped 1.04 s after a ban. Idle ping p95 was 30.8 ms before the restart
  and 32.4 ms afterward (30 replies per sample).
- In the same Linux development build, a saturated TCP flow reached
  28.45 Mb/s and only 18 of 30 pings received a reply. A follow-up
  development run counted 1,049 drops at the sending TUN device and
  108 transmit-admission refusals across the session transmitters.
- An optimized Linux ARM64 A/B run used the same daemon binary in both
  cases, real TUN interfaces, MTU 1280, 1,100-byte UDP payloads, and
  isolated single-direction loads of 4, 16, 32, 64, and 128 Mb/s.
  The build used the release profile with LTO disabled and 16 codegen
  units to fit the stand. At 128 Mb/s the baseline missed 2 of 101,818
  datagrams across both directions. The copy-free batch send missed
  none in its run. At that step each build received all 120 ping
  replies, with worst per-probe p99 of 3.68 ms and 4.08 ms respectively.
- Over three saturated TCP runs the baseline reached 505–547 Mb/s
  with 78 of 90 ping replies. The change reached 498–531 Mb/s with
  85 of 90 replies. This short stand comparison establishes no
  throughput gain. Session transmit-admission refusals remain.
- The optimized bridge recovered after daemon restart with the same
  process and TUN interface, and blocked a banned peer, with and
  without packet batching. The prepared batch encoder emits exactly
  the prior IPC bytes, including the local scheduling lane. Pending
  batches also check the active address assignment before submission.
- A short-lived signed member certificate passed traffic before expiry.
  At expiry, probes failed in both directions while the TCP session
  and TUN interface were still present.
- With the real IPC server and a synthetic admission provider, complete
  route installation for 34, 256, and 1,024 configured peers took about
  0.13 s, 0.50 s, and 2.00 s respectively. Full withdrawal took about
  4.88 s in each case, including the wait for the next sweep. The 1,024
  entries went through 16 IPC requests per sweep.
- On two Linux ARM64 nodes with real TUN interfaces and one live certified
  peer at the end of each configured list, the routes appeared within
  0.22 s for 34 entries, 0.66 s for 256, and 2.17 s for 1,024 after
  starting ogate against established daemon sessions. In the 1,024-entry
  run ogate used about 0.1% of one CPU core when idle and at most 0.72%
  with bidirectional pings. These are short process CPU samples.
- In the mixed Linux run with 34 entries and the same new ogate on
  both nodes, startup took 4.36 s with the pre-batch daemon
  (`7f30dbd3`) and 0.20 s with the new daemon. The nodes passed TUN
  traffic both ways. The old daemon still served the single-peer query.
- With 1,024 entries and 62.6 Mb/s offered UDP traffic on the Linux
  stand, a ban withdrew the route in 4.78 s. While the sender kept
  running, the receiver's TUN counter stopped advancing after withdrawal.

## 3. Distribute owner-authorized peer policy

- Sign a versioned snapshot of virtual address assignments with the
  configured network owner key. Give the canonical bytes a policy-specific
  signature domain and bind them to the network ID, revision, validity
  window, address ranges, and member Node IDs.
  Validate the signature and the whole address map before publishing it.
  Require unique addresses and reject assignments outside the signed ranges.
- Persist the accepted snapshot together with its revision in one durable
  update. After restart, keep the revision floor even if the last policy
  has expired. Accept an equal revision only for an identical snapshot.
  A disconnected node can resume with its cached policy until expiry.
  An expired snapshot contributes zero routes.
- Start with opt-in distribution through local policy files and qualify
  restart, expiry, and rollback behavior. Preserve the existing manual
  peer list for deployments that have yet to adopt signed policy.
  In signed mode require both a current assignment and current admission
  from the daemon on the same private network. A ban still withdraws access.
- Qualify automatic delivery over authenticated private Veil sessions.
  Apply the same signature, revision, and address checks as local delivery.
  Define owner-key rotation and recovery on the configured trust anchor
  before automatic rollout.
