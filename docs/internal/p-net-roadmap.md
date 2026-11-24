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
- At the legacy query pace, 1,024 configured peers take about 128 s
  to sweep. Qualify a negotiated IPC status query for bounded groups of
  configured peer IDs. Reuse the same live-session, membership, ban,
  and expiry checks and bound the work per connection. Measure sweep
  CPU and worst-case admission and revocation delay at 34, 256, and
  1,024 peers, including while packets are flowing.

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

## 3. Distribute owner-authorized peer policy

- Specify a signed policy for membership and virtual address allocations.
  Bind it to the network ID and owner, persist the newest accepted revision,
  and define behavior for expired policy, replay, conflicting addresses,
  and a disconnected node rejoining the network.
- Stage adoption in parallel with locally configured peers. Define migration,
  revocation and owner-key rotation before deploying automatic policy
  updates. Keep private traffic gated on verified membership throughout.
