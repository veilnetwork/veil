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
- Extend shared-daemon qualification to long contention runs, disjoint
  route tables, and many simultaneous live peers.
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
- ogate uses the daemon's existing local session events to start admission
  sweeps earlier when it negotiates batch queries. It coalesces events
  for 100 ms and paces early rechecks based on table size. Between
  batches, the bridge checks for a queued event and gives a due recheck
  priority over the next ordinary batch. The periodic sweep covers
  missed events and changes that leave a session open. Route decisions
  still use the daemon's admission query. In the same IPC test, a burst
  of 64 events took about 0.13 s to withdraw 34 routes and 2.00 s to
  withdraw 1,024 routes. On Linux ARM64
  with a real TUN and the live peer last in a list of 1,024, route
  installation after admission took 2.12 s (previously 4.34 s). Route
  withdrawal after disconnect took 1.82 s (previously 4.34 s). The
  mixed-version run with a pre-batch daemon used the single-peer queries,
  passed traffic in both directions, and withdrew the disconnected
  peer's route. In a separate Linux ARM64 run with 4,096 configured
  peers, the live route returned 4.75 s after admission even though a
  truncated peer-list reply omitted that peer. The gateway queried it
  in the second batch and passed TUN traffic in both directions.
- A peer-list query triggered by a session event can retry once after
  its 250 ms timeout. The retry uses the existing 125 ms query pace.
  The daemon echoes the request ID in `PeersList`, so a late reply to
  the first query cannot satisfy its replacement. An IPC test with a
  delayed empty list reproduced the missed route restoration for a
  table with 4,096 entries and passed with both changes. The peer list
  schedules queries. Route admission still requires a current positive
  membership result.
- On two Linux ARM64 peers with real TUN interfaces, an IPC proxy
  dropped the first peer-list reply after reconnect in each trial.
  With 4,096 configured entries, route restoration after the daemon
  reported admission took 6.42 s on the previous bridge and 5.59 s
  with the retry. Both used the same older daemon. The candidate
  retried on the same connection with a new request ID. Both trials
  passed encrypted traffic in both directions after the restart and
  rekey. The echo path for zero and nonzero request IDs is covered by
  a separate Unix IPC test.
- A separate mixed run used a pre-batch daemon with 34 configured
  entries. The tunnel passed traffic in both directions, and the new
  bridge removed the route 0.879 s after disconnect.
- For manually configured routes, ogate remembers up to 256 recent
  withdrawals confirmed by the daemon. If the peer list requested after
  an event is full or unavailable, free slots in the priority batch can
  recheck those peers for up to 30 s after withdrawal. The bridge avoids
  duplicate queries for peers selected from the list. Newly installed
  routes still require a positive admission response.
- On Linux with real TUN interfaces, a proxy replaced the post-rejoin
  peer list with 256 entries that omitted the rejoining peer. With 4,096
  configured routes, the earlier bridge restored the route after 6.12 s
  using a 64-entry sweep batch. The updated bridge restored it after
  3.40 s using a two-entry priority batch. Withdrawal took 1.70 s and
  2.25 s in the two trials. Both passed encrypted traffic in both
  directions after rejoin. The socket regression test also checks that
  a configured peer listed as active without admission has no route.
- When a peer list is below its cap, the event-triggered batch now checks
  open routes whose peers disappeared before checking new joins. The
  ordinary sweep and the 64-entry batch limit are unchanged. In the
  Unix IPC test with 4,096 configured routes and 64 simultaneous joins,
  the previous bridge missed a two-second withdrawal deadline. The
  update checked the departing peer first and removed its route within
  the deadline. A joining peer without admission remained unroutable.
- When at most one eighth of configured peers have admission, ogate
  builds the published route table from their existing assignments.
  It uses the full-table filter for denser admission. A macOS ARM64
  process-local comparison used 4,096 dual-stack assignments. Median
  projection time went from 242.32 to 0.32 µs for two admitted peers
  and from 251.72 to 11.40 µs for 64. With all 4,096 peers admitted,
  both paths took about 471 µs. This measures construction and drop of
  the routing snapshot. Each projection kept the same peer app IDs
  and expiry values.
- A Linux ARM64 QUIC pair with real TUN interfaces and 4,096 configured
  routes passed traffic in both directions and delivered all 48 SDK
  chat messages exactly once. The tunnel route was gone 2.23 s after
  loss of daemon admission. A mixed run with a pre-batch daemon,
  34 routes and raw TUN packets passed the same checks and withdrew the
  route in 1.13 s.
- On three Linux ARM64 nodes with 1,024 routes per node and 32 Mb/s of
  offered UDP on the surviving link, three A/B runs measured route
  withdrawal of 1.72–1.94 s with session events and 3.75–3.78 s with the
  previous bridge. The surviving link returned all 100 pings per run.
  Across the short runs, ping p99 ranged from 3.13 to 6.42 ms with events
  and from 3.25 to 3.98 ms with the previous bridge. One of 87,170 UDP
  datagrams was lost with the change. The previous bridge delivered
  all 87,276 datagrams.
- A daemon that reaches its shared admission-lookup quota now allows
  batches to wait for refill off the IPC connection loop. The daemon
  holds at most 32 outstanding batches for lookup and each may wait up
  to 550 ms from enqueue. A full queue of 64-peer batches needs 500 ms
  of refill from an empty budget, with 50 ms allowed for timer and
  dispatch overhead. The lookup budget allows a burst of 1,024 checks
  and refills at 4,096 checks/s. The daemon reads current admission after
  the wait and replies using the original request ID and frame format.
  With the earlier 250 ms deadline, only 16 of 32 queued full batches
  completed in a paused-clock test. All 32 complete with the new deadline
  at the same refill rate.
- An isolated 85 s Linux ARM64 A/B run used twelve ogate instances sharing
  one daemon, 1,024 configured routes per instance, one flapping member
  and one stable member offering UDP at 32 Mb/s. Both runs used the same
  ogate binary and test-only identity difficulty. With the old daemon the
  gateways logged 57 failed batch queries and every gateway dropped the
  stable member's route at least once. With the queue all eight session
  changes converged in 2.55–3.35 s after the daemon reported the transition.
  The gateways logged zero failed queries and all kept the stable
  member's route. The stable link delivered 309,092 of 309,092 UDP
  datagrams and 1,054 of 1,054 ping replies. Previously it delivered
  265,236 of 308,901 UDP datagrams and 905 of 1,041 ping replies.
  Ping p99 was 5.27 ms with the queue and 5.02 ms before the change.
- A 180 s Linux ARM64 run with 16 disjoint tables of 1,024 entries and
  32 authenticated members used the original 250 ms queue. All 14
  transitions converged within 4.05 s after the daemon confirmed the
  session change. No gateway lost the stable member's route or logged
  a failed batch query. Two 16 Mb/s UDP flows delivered 654,300 of
  654,363 datagrams. The 16 ICMP probes received 11,321 of 11,489 replies.
  Some probes still saw seconds of delay. The worst per-probe p99 was
  5.21 s and the longest gap between replies was 8.27 s. The cause of
  these delays is still open.
- The next 110 s Linux ARM64 A/B run used 24 disjoint tables of 1,024
  entries and 48 authenticated members. Both runs used the same ogate
  binary and test-only identity difficulty. At 250 ms the 24 gateways
  did not finish setting up all routes within 22 s. One of eight paired
  session transitions converged within the 9 s measurement window.
  With the 550 ms deadline, setup finished in 6.10 s and all eight
  transitions converged in 0.33–7.11 s. Failed batch queries fell from
  185 to nine. Nine gateways briefly lost the unaffected member's route,
  down from 24. The two 16 Mb/s UDP flows delivered 383,149 of 394,993
  datagrams, up from 305,002 of 400,002.
- That run also recorded multi-second ICMP latency on nine gateways
  whose routes stayed installed. On the new daemon, all 245 ICMP
  replies taking at least a second arrived within the first 9.53 s of
  the traffic sample. The worst per-probe p99 after the first 15 s was
  13.8 ms. The central TUN counters reported zero kernel drops. The
  startup delay and the remaining failed admission queries need
  separate investigation.
- The startup log traced multi-second sends to device-certificate
  discovery. A live recipient's identity document and instance registry
  can now arrive in parallel. Other recipients must establish a verified
  document before the registry query starts. Overlapping requests share
  registry and certificate candidate bytes, including the direct
  instance certificate walk. Every caller verifies signatures, compares
  freshness, and checks the current authorization before using a key.
- With a silent replica, the maximum-size family fixture resolved in
  15 s, compared with 18 s when the two metadata waits ran in sequence.
  A cold 60 s Linux ARM64 A/B run with 16 gateways, 32 authenticated
  members and two 16 Mb/s UDP flows used the same bridge binary and
  test-only identity difficulty. The longest logged family resolution
  dropped from 9.00 to 6.01 s. The worst per-probe ICMP p99 dropped from
  7.50 s to 18.1 ms. Replies taking at least a second fell from 85 to
  seven. ICMP delivery was 3,840 of 3,840 compared with 3,735 of 3,834.
  The UDP flows missed 22 of 218,184 packets, previously 124 of 218,025.
  Both runs converged on all four session transitions without failed
  admission queries.
- Repeating the 110 s run with 24 gateways, disjoint 1,024-entry tables,
  and 48 authenticated members on the newer resolver reached all initial
  routes in 5.93 s. All eight transitions converged in 1.03–5.06 s. No
  batch query failed or caused a route withdrawal for a live member.
  ICMP delivery was 10,536 of 10,536 with a worst per-probe p99 of
  13.5 ms. The two UDP flows delivered 399,664 of 399,704 packets.
- ogate retries a batch once after two seconds without a reply. The
  replacement uses a fresh IPC request ID and the existing query pace.
  It shares the original five-second deadline. A late approval for
  the first request cannot override a denial for the replacement.
- A 40 s Linux ARM64 A/B run used 24 gateways, 48 authenticated
  members, and an identical daemon binary. A local IPC proxy dropped
  one status-batch reply at each of 22 gateways. Previously all 22
  cleared their routes. All 22 retries succeeded and no routes were
  cleared with the change. ICMP delivery rose from 3,364 of 3,831
  replies to 3,839 of 3,840. The longest reply gap fell from 6.15 s
  to 0.64 s. The two unproxied UDP flows delivered 144,865 of 145,413
  packets with the change, compared with 144,993 of 145,018 in the
  control run. A socket regression test also verifies that two missing
  replies exhaust the original deadline and yield no admission result.
- In that first fault run, 535 of the 548 missing UDP datagrams were
  from one unproxied tunnel. Its routes stayed installed, its bridge
  logged no admission retries or failures, and its receiving TUN recorded
  zero kernel drops. The two runs had different session directions and
  reconnect counts.
- Two controlled repeats reused the same 48 identities and daemon
  binary with 24 gateways. In the 42 s run with the spokes dialing the
  hub and no fault injection, loss across the two UDP flows was
  19 of 152,670 with the previous bridge and 12 of 152,347 with the retry
  change. All four senders began after their routes were installed.
  In the 36 s repeat with the hub dialing, both flows exchanged packets
  before sampling and the proxy dropped 22 status replies on other
  gateways. Loss was 3 of 130,824 and 9 of 130,912 respectively.
  All 22 retries succeeded and all routes stayed installed with the
  change. The earlier UDP loss spike did not recur in either comparison.
  Its exact cause remains open.
- On a new batch-capable status connection, ogate uses the bounded IPC
  session list to put live peers first in large admission sweeps. Every
  configured entry stays in the sweep and still requires its own positive
  P-Net admission result. Manual gateways can also keep recently
  admitted peer IDs when either IPC connection is lost. Those hints
  expire after 30 seconds. A new sweep places currently observed live
  peers first, then the recently admitted configured peers, and
  checks each peer against the daemon's current admission result.
  The recent hints also work with the legacy single-peer query.
- An optimized macOS ARM64 microbenchmark with 4,096 entries and
  48 live peers rebuilt the sorted check order in 4.65 µs, compared
  with 107.42 µs before. With 256 live peers it took 11.00 instead of
  95.16 µs. On an already rearranged order with 48 hints it took
  53.64 instead of 101.47 µs. These timings cover the in-memory
  selection and copying of the sweep order.
- On the same 48 authenticated sessions, 24 gateways checked disjoint
  4,096-entry tables with both live peers at the end of each table. All
  routes appeared 2.56 s after launching the updated gateways, compared
  with 24.19 s with the previous ogate. A second launch of the updated
  gateways took 0.84 s. The three samples used the same running daemon.
  During the following 164 s of traffic, the gateways logged no failed
  admission batches and kept all unaffected routes. The probes received
  all 15,719 ICMP replies, and the two UDP flows delivered 596,195 of
  596,215 datagrams. Under this load, route withdrawal still took
  14.62–18.78 s after the daemon reported the session loss, and one
  recovery took 21.23 s. In that build, session changes waited for a
  sweep boundary.
- A session count change or committed session event can now schedule one
  admission batch during a large sweep. ogate compares the bounded IPC
  session list with its admitted routes, checks likely joins and
  departures, then resumes the sweep at the same cursor. The batch uses
  the existing query pace and retry deadline. At the session list's cap,
  the full sweep continues to check peers missing from the list.
- On a sparsely populated gateway, session changes use indexed routing
  lookups for the affected peers. Candidate ordering still puts possible
  departures before joins, and the existing batch limit, IPC pace, and
  admission rules apply. Dense tables keep the original selection path.
- In an optimized macOS ARM64 microbenchmark with 4,096 configured routes,
  selection with 48 live sessions took a median 1.0 µs with no changes
  and 1.3 µs with six withdrawals and six joins, compared with 107.8
  and 107.2 µs before. A 256-entry capped session list took 6.7 µs
  versus 20.4 µs. With 1,024 admitted peers, the dense path took about
  5.1 µs in both variants. These timings measure candidate selection
  in memory.
- Two Linux ARM64 gateways with 4,096 configured routes each passed
  bidirectional TUN traffic after a late join, with the route added
  within 0.32 s of observing admission. A separate two-gateway run
  withdrew the route 5.26 s after detecting session loss. Bidirectional
  traffic resumed on the original TUN interfaces 2.47 s after observing
  readmission. With a pre-batch daemon and 34 configured routes, the
  equivalent intervals were 0.88 s for withdrawal and 6.63 s for
  bidirectional recovery. Both disconnect runs delivered all 48 SDK
  chat messages exactly once before the restart.
- A session count hint can schedule an earlier admission batch while
  the ordinary session snapshot is cooling down. If all installed
  routes fit in one batch, the gateway looks them up directly. For
  more than 64 installed routes, it asks for one peer snapshot and
  checks installed peers absent from it. With a truncated or missing
  snapshot, each new early check starts after the last candidate and
  wraps around the table. The gateway schedules at most one early
  round per second using the shared IPC pace. Only the daemon's
  admission reply changes routes. The pending snapshot and full
  sweep still cover discovery and the routes outside the early batch.
- With 97 installed routes out of 4,096 configured, a local IPC
  regression test withdraws one route within its 2 s deadline during
  the ordinary snapshot cooldown. The other 96 stay installed. A
  separate test checks that truncated snapshots advance through
  successive batches and wrap around the table. A Linux ARM64 TUN
  check with this change also passed session recovery on the same
  interfaces and delivered all 48 SDK messages with both current and
  pre-batch daemons.
- In a three-node Linux ARM64 test, a gateway with 4,096 configured
  routes admitted a second peer just before losing its first session.
  Alternating builds with the same daemon binaries, the two controls
  withdrew the first route 4.80 and 4.78 s after the stand detected
  the session loss. The updated gateway used one early admission batch
  and withdrew it in 0.087 and 0.083 s. The second route passed
  bidirectional traffic after withdrawal. Restarting the first peer
  restored traffic on the same TUN interfaces. In each run and a
  separate mixed-version run with a pre-batch daemon, all 48 SDK chat
  messages sent before the disconnect arrived exactly once.
- A two-vCPU Linux ARM64 stand exercised 66 live authenticated
  sessions on a single gateway with 4,096 configured routes. Each
  run admitted a new peer, disconnected a different peer, and then
  restored it. The four runs used the same daemon binaries and
  identities and alternated the gateway builds in control, candidate,
  candidate, control order (`6b1a26a9` and `ec29eeee`). Two
  unaffected spokes sent 1,100-byte UDP datagrams at 16 Mb/s each
  for 18 seconds per run, concurrent with bidirectional SDK chat.
- After the daemon reported session loss, route withdrawal took 4.41
  and 4.93 s with the control and 0.293 and 0.266 s with the candidate.
  All 261,510 UDP datagrams and all 384 SDK chat messages arrived
  exactly once. Bidirectional tunnel recovery after observed
  readmission took 3.13 and 2.66 s with the control and 4.11 and
  4.46 s with the candidate, on the original TUN interfaces. The
  earlier withdrawal still left recovery dependent on the ordinary
  session snapshot's cooldown.
- A committed session admission event can use the same early slot to
  retry recently withdrawn routes while the snapshot is cooling down.
  It checks only configured peers, uses the existing cache expiry and
  round-robin cursor, and waits for a positive daemon admission reply.
  Loss and readmission checks share one early round per second.
  An empty retry group consumes no query slot. Local IPC tests cover
  recovery during the cooldown, including when a truncated peer list
  omits the rejoining peer.
- In an alternating three-node Linux comparison with 4,096
  configured routes, the gateway published the returning peer's
  route 0.333 and 0.341 s after the stand observed readmission.
  Controls based on `ec29eeee` took 1.15 and 2.82 s. The
  bidirectional TUN check was separate. It took 0.51–3.08 s with
  the change and 2.62–2.98 s with the control.
- On the 66-session stand, eight comparable manual-policy runs and
  one signed-policy run delivered all 587,948 UDP datagrams and all
  864 SDK chat messages. The manual-policy bidirectional check
  after readmission ranged from 0.33 to 2.84 s with the change and
  0.40 to 2.94 s with the control. The signed-policy run recovered
  in 0.34 s. Two additional attempts at separate timing did not
  meet the stand deadlines for session establishment or warm-route
  publication.
  A separate run with a pre-batch daemon passed bidirectional
  recovery and delivered all 48 SDK chat messages.
- A matched Linux run reused the daemon, 48 authenticated identities and
  24 disjoint tables of 4,096 entries. Spokes initiated the sessions so
  their restarts could exercise route recovery without waiting for the
  hub's reconnect schedule. Measured from the daemon's admission change,
  the two withdrawals took 5.71 and 1.81 s, previously 12.95 and 20.74 s.
  The two restorations took 5.96 and 1.78 s, previously 4.94 and 12.92 s.
  Both affected paths answered ICMP after each restoration. A separate
  run timed out waiting for session establishment before it could
  measure route recovery.
- During both 132 s traffic samples, no batch failed and every
  unaffected route stayed installed. The updated gateways received all
  12,648 ICMP replies and 479,740 of 479,766 UDP datagrams. The control
  received 12,646 of 12,648 replies and 478,167 of 478,742 datagrams.
  One control flow missed 567 datagrams with zero kernel TUN drops and
  its route still installed. Its first ICMP replies saw up to 3.24 s
  of delay. Later probes returned to the usual latency.
- Packet sequence probes at both TUN interfaces and the receiver socket
  reproduced a burst on a two-vCPU Linux stand with the same daemon and
  ogate builds. Twenty-four gateways started ICMP probes alongside two
  16 Mb/s UDP flows. The first 38 s sample lost 4,100 of 135,287 UDP
  datagrams, mostly in its first eight seconds. The warm repeat lost
  three of 138,184. The sending TUN taps saw every datagram. The receiving
  tap and UDP socket saw the same packets. Capture and UDP socket drops
  were zero. Device-certificate walks overlapped the early losses.
- A fresh repeat warmed the two measured paths before offering traffic
  and left the other gateways cold. One flow missed 1,039 datagrams,
  including 1,028 in the first two seconds. Its sending daemon logged a
  full session TX channel during that interval. The TX drop counter rose
  by 122 frames in the first 1.35 s and by 146 over the sample. The
  receiving application and IPC delivery drop counters stayed at zero.
  Frame counts alone cannot determine the contribution of each traffic
  class to the missing datagrams.
- A follow-up traced frame metadata at the sending queue. Of 711 logged
  admission refusals on the two measured spokes, 690 were
  `AppSendSealed` frames on the local recoverable lane, mostly around
  3.6 KB. The other 21 were `Forward` frames on the same lane. The
  trace observed the existing queue result and recorded no payloads.
- Small sealed private-network sends on this lane can wait up to 250 ms
  for the existing source credits. A resumed send rechecks its proven
  session instance, revocation status and membership expiry. Expiration
  ends the admission attempt without a relay retry. The existing
  `AppSendSealed` frame and source queue budget apply.
- A 34 s cold A/B run reused 48 identities and 24 gateways. The two
  senders' immediate session TX refusals went from 175 to zero. UDP loss
  was 2,606 of 121,137 datagrams with the change and 3,670 of 123,513 in
  the control. The two flows changed from 9 and 3,661 losses to 626 and
  1,980 respectively. TUN captures and UDP receive sockets reported
  zero observation drops. Loss between the TUN taps still needs
  attribution at IPC admission and during the bounded credit wait.
  A separate two-node mixed-version run passed traffic both ways and
  withdrew the route after the pre-batch peer disconnected.
- A second 34 s A/B run added a bidirectional Veil SDK chat to one of
  the sessions carrying the two 16 Mb/s UDP flows. Each chat endpoint
  submitted 155 direct 96-byte messages at five per second. The control
  delivered 308 of 310 and the credit-wait build delivered all 310,
  with no duplicates in either run. From hub to spoke, p95 went from
  44.8 to 63.5 ms and p99 from 106.4 to 101.0 ms. From spoke to hub,
  p95 went from 33.4 to 100.9 ms and p99 from 86.9 to 212.6 ms. This
  single comparison covers the direct SDK path under contention.
- A lab-only sequence trace in the credit-wait build accounted for all
  122,581 UDP datagrams. The source daemons read every datagram from IPC.
  On one spoke the daemon returned `SERVER_BUSY` before starting the
  send job for all 413 missing datagrams, in the fourth and fifth seconds
  of the run. All admitted datagrams entered the handler, obtained
  direct session credit, and reached the destination socket. Both TUN
  captures and the receive sockets reported zero observation drops.
  Further work on cold-start loss should therefore measure the pending
  IPC job budget separately from the first-hop credit wait.
- The daemon exports separate `SERVER_BUSY` counters for the outstanding
  job limit, the per-connection byte limit, and the shared byte limit.
  A second trace with 24 gateways found 603 and 521 job refusals on the
  two senders with the default 200 µs batching window. Both byte-limit
  counters stayed at zero. At peak saturation, four jobs were waiting
  on direct session admission and 124 had yet to enter the handler on
  each affected connection. The p99 seal times were under 0.1 ms on
  both senders. All 3,821 datagrams missing between the TUN taps matched
  refused jobs. The receive socket dropped another 28 datagrams locally.
- With the same binaries and peer identities, setting the existing
  `batch.flush_after_us` to `1600` on the two UDP senders reduced the
  number of UDP requests sampled in the first 22,000 datagrams per flow
  from 15,613 to 8,225. Job refusals fell from 1,124 to 100 and the
  number of datagrams refused by those jobs fell from 3,821 to 511.
  The destination tap and socket each reported five capture or receive
  drops on one flow. Both configurations delivered all 310 direct SDK
  chat messages. The spoke-to-hub chat p99 rose from 410 to 574 ms and
  the hub-to-spoke p99 rose from 211 to 226 ms. The default stays at
  200 µs. These are two cold trials on a two-vCPU Linux ARM64 stand.
- On a cold repeat using the existing session trace, the two transmitting
  spokes logged 56 and 74 TCP writes taking at least 25 ms, peaking at
  271 and 132 ms. The write delays overlapped the measured IPC refusals.
  The sessions used the canonical ordered writer, with neither a parallel
  transport nor an active primary media producer. The hub made 24
  cold recipient-certificate walks and logged 21 slow inbound dispatches.
  The destination TUN probes dropped 17 and 46 observations, and one
  receive socket reported 27 drops. The write and IPC observations are
  taken at the sender and do not depend on the destination captures.
- For an active private member, the node sends an existing Discovery
  `Store` with its current signed instance certificate after the identity
  document notice. It validates the locally published certificate against
  the current device, key material, delegation, and expiration. It checks
  membership expiry, ban status, and TX ownership on the admitting
  session. The receiver uses the normal DHT store quotas and certificate
  verification on resolution. Normal discovery still serves cache misses.
- In the initial controlled test of the notice, hub instance-certificate
  walks fell from 17 to zero. Sender IPC refusals fell from 114 requests
  covering 330 UDP datagrams to zero. Both trial variants delivered all
  310 direct chat messages. Spoke-to-hub chat p99 fell from 246 to 108 ms.
  The same two senders logged 65 slow TCP writes without the notice and
  32 with it. The 121,904 datagrams in the notice run all reached the
  receiver socket, with zero TUN capture or socket drops.
- A repeat ran the production change first and the control second. Hub
  certificate walks were zero and 16 respectively. Slow TCP writes from
  the two senders were 40 with the change and 63 in the control. IPC still
  refused 1,568 datagrams with the change and 1,267 in the control. The
  changed run also recorded 80 drops across the destination UDP sockets.
  Both runs delivered all 310 direct SDK messages. The hub-to-spoke p99
  changed from 202 to 149 ms and the spoke-to-hub p99 from 311 to 400 ms.
  The repeated result is removal of the cold certificate walks. UDP loss
  and chat tail latency still vary when the ordered transport is loaded.
  The production change also passed TUN traffic in both directions with
  a pre-batch daemon and withdrew the route 0.88 s after its session closed.
- On the message path, a resolver can skip cloning and parsing the same
  document when the shared authorization floor matches its applied digest
  and the local DHT copy is absent or has the same digest. The floor check
  still applies expiry and retries pending file writes. Changes in either
  source go through the usual validation and key retirement path.
- A 23 s paired stand run sampled thread CPU time inside the document
  refresh on the hub, once per 64 calls. In 621 control and 606 changed
  samples, median CPU time fell from 3.38 to 1.29 µs and p95 from 5.92
  to 2.04 µs. Both variants delivered all 200 SDK chat messages. The
  spoke-to-hub chat p99 fell from 441 to 261 ms in this pair and rose
  from 386 to 420 ms in the earlier 34 s pair with the build order
  reversed. IPC attributed 592 versus 723 UDP refusals in the short
  pair and 2,443 versus 4,083 in the longer pair. Cold ordered-transport
  contention remains even with the cheaper identity refresh.
- A Linux TCP socket trace sampled both ends of the two tunnel flows
  every 125 ms. The 24-gateway cold run passed all 82,799 datagrams at
  16 Mb/s per flow. At 32 Mb/s per flow it refused 2,959 of 166,984 at
  source IPC. Across the ten metrics intervals with job refusals, the
  sender's receive-window-limited time increased every time and its
  send-buffer-limited time did not increase. Unread bytes in the two
  matching hub TCP sockets peaked at 4.0 MB and 1.15 MB in those windows.
  The destination UDP sockets dropped another 310 datagrams locally.
- The warm 32 Mb/s repeat used the same established TCP sessions. It
  delivered all 167,274 datagrams and added no receive-window-limited
  time on either sender. The corresponding hub receive queues peaked
  at 14,412 and 11,331 bytes. The hub daemon's Tokio threads accumulated
  7.06 s of runnable wait in the first 11 cold seconds versus 2.26 s over
  the entire 23 s warm sample. These samples include competition from
  the other daemons and gateway processes sharing the two-vCPU host.
- In a separate cold pair at 32 Mb/s per flow, switching the 24 hub
  ogate processes to the existing single-thread runtime moved refusals
  from 4,688 and 4,617 datagrams to 5,883 and 2,070 on the two flows.
  Both runs delivered all 200 SDK chat messages, with spoke-to-hub p99
  rising from 573 to 782 ms. Both TCP senders still encountered
  receive-window pressure. The default runtime stays in place.
- Outbound IPC route selection uses indexed TX liveness lookups for the
  target devices. It no longer builds the full list of active sessions
  on each check. The live registry excludes closed sender channels even
  when their entries are still awaiting cleanup. A macOS mixed-version
  run delivered 1,000 SDK messages in each direction in public mode and
  repeated the same delivery count with private membership enabled.
- Private admission checks reject peers absent from the verified certificate
  cache before acquiring the session registry or TX registry locks. Peers
  with a cached certificate still go through the normal session owner,
  expiry, and ban checks. The single-peer status query retains its public
  session semantics. All batch entries still count against the lookup
  budget, including misses.
- Two Linux ARM64 pairs ran the same instrumented daemon with and without
  the early check, reversing the trial order. The two-vCPU stand ran 24
  gateways with 4,096 configured entries each and two 32 Mb/s UDP flows.
  The p95 thread CPU time per sampled admission lookup fell from 1.25 to
  1.04 µs in both pairs. The first pair delivered every UDP datagram. In
  the reverse pair, the control lost 21,814 of 162,892 datagrams and the
  early check lost 21,438 of 164,130. Neither sender reported a UDP socket
  send error. Both variants still encountered TCP receive-window pressure
  during cold startup.
- Each of the four trials delivered all 200 SDK chat messages. Chat p99
  increased from 6.4 to 10.4 ms towards the hub and from 6.6 to 29.8 ms
  from the hub in the first pair. In the reverse pair it increased from
  403 to 742 ms and from 170 to 233 ms respectively. The latency increase
  needs investigation on the shared host. In a separate mixed-version
  run with a pre-batch daemon and 34 entries, the tunnel passed traffic
  in both directions and withdrew the route 1.142 s after disconnect.
- Matching each chat sequence to its send time in the overloaded repeat
  tied the high latencies to receive backlog on the transport shared with
  the second UDP flow. For messages towards the hub that took at least
  100 ms, the median peak receive queue within 125 ms of send was 357 kB
  in the control and 1,032 kB with the early check. For messages taking
  at most 30 ms, it was zero in both. Hub daemon threads also accumulated
  more runnable wait during the high-latency periods. The control recorded
  a median of 128 timed lookups per second in both latency groups, timing
  one lookup in 32. The contribution of the early admission check to the
  queue growth remains unresolved.
- A transport pair held the authenticated identities, binaries, 24
  disjoint 4,096-entry tables, and two 32 Mb/s UDP flows constant. The
  first TCP sample lost 11,034 of 166,003 datagrams, including 94 drops
  counted at receiving UDP sockets. Hub TCP receive queues exceeded
  1 MB on both flows. The TCP repeat on the same sessions delivered all
  166,926 datagrams, with receive queues below 32 kB. The hub recorded a
  median of 128 timed lookups per second in both TCP samples, timing one
  lookup in 32.
- The first QUIC sample lost 526 of 166,982 UDP datagrams, matching the
  local drops reported by the receiving application sockets on both
  flows. These socket counters are independent of the TUN capture, which
  also lost observations. The QUIC repeat delivered all 167,276 datagrams.
  Both transports delivered all 200 SDK chat messages per sample. In the
  first samples TCP and QUIC chat p99 towards the hub were 486 and 43 ms.
  In the opposite direction they were 132 and 15 ms. In the repeats they
  were 0.79 and 1.06 ms towards the hub, and 1.20 and 1.68 ms from the hub.
  The QUIC trace recorded established parallel children and received
  datagrams. Both transports used the existing private membership checks.
- A reverse-order cold pair disabled runtime traces and admission timing.
  QUIC delivered all 166,983 UDP datagrams and TCP all 167,275. Each
  delivered all 200 chat messages. QUIC chat p99 was 23.95 ms towards
  the hub and 23.82 ms in reverse. The TCP p99 was 2.65 and 2.23 ms.
  Cold TCP congestion varied across the pairs. These short runs on one
  two-vCPU host leave the effect of tracing and the transport choice
  under reproducible saturation open.
- A mixed-version QUIC pair with the pre-batch daemon used the legacy
  single-peer admission query and passed real TUN traffic both ways.
  Both directions delivered all 24 SDK chat messages. The current side
  withdrew the route 1.404 s after the legacy session disconnected.
- Another pair began with 23 seconds at the same UDP rates with no
  CPU quota on the hub. TCP lost 6,438 of 164,784 datagrams and QUIC
  2,159 of 162,467. The missing sequences matched 6,166 and 2,042 IPC
  refusals, with the respective remaining 272 and 117 counted by local
  UDP receive sockets. Towards the hub chat p99 was 639 ms on TCP and
  1,696 ms on QUIC, with the largest waits beginning five to seven
  seconds into the load. Both runs delivered all 200 chat messages.
- On the same established sessions, a second 23-second sample put the
  hub container, the 24 gateways and the receive probes under a combined
  quota of 50 ms CPU per 100 ms. Both transports delivered every UDP
  datagram and chat message. Hub use averaged 0.34 CPU on TCP and 0.33 on
  QUIC. Linux reported zero throttled periods, and chat p99 in either
  direction stayed below 2 ms on both transports.
- The reverse-order pair used a tighter quota of 28 ms per 100 ms for
  the second sample. Linux throttled the hub in 166 of 229 periods on TCP
  and 227 of 229 on QUIC. Each sample delivered all 167,276 UDP datagrams
  and 200 chat messages. Chat p99 towards the hub was 2.67 ms on TCP and
  2.40 ms on QUIC, with 1.57 and 1.55 ms in the other direction. The
  sustained quota exercise left startup contention as a separate issue.
- In the first samples of that pair, before setting the quota, TCP lost
  3,892 of 166,614 UDP datagrams and QUIC lost 6,900 of 162,282. The IPC
  refusal sequences accounted for 3,806 and 6,842, and receiving UDP
  sockets counted 86 and 57 drops respectively. One lost QUIC datagram
  remains unattributed. TCP delivered all 200 chat probes, with p99 of
  209 ms towards the hub. On QUIC the hub received 96 of 100 probes with
  p99 of 2,255 ms among those received. The other endpoint received all
  100. These probes used `AppSender::send` without an end-to-end receipt.
- A separate Flutter test ran the xVeil `MessagingService` with its native
  Veil client and in-memory journal backing. The two endpoints completed
  the contact handshake before starting UDP. Each sent 48 text messages
  on the direct private-network path, at five messages per second. The
  Linux QUIC stand used 24 gateways with 4,096 entries each and two
  32 Mb/s UDP flows. It delivered all 167,208 UDP datagrams. All 96 texts
  appeared in recipient history exactly once and were marked delivered
  at their senders. The test polled history every 50 ms and observed a
  57 ms arrival p95 and 66 ms receipt p95 in both directions.
- At the same offered rates on TCP, the xVeil test delivered and
  confirmed all 96 messages. The arrival p95 was 54–55 ms and the
  receipt p95 was 64–65 ms. The 260 missing UDP datagrams out of 167,061
  matched the loss counts at the receiving application sockets.
- At two 64 Mb/s UDP flows on TCP, the xVeil test again delivered and
  confirmed all 96 texts, with no duplicate history entries. Arrival
  p95 was 79 ms from the hub and 132 ms towards it. Receipt p95 was
  144 ms and 132 ms respectively, and the longest receipt took 431 ms.
  The UDP receivers got 330,010 of 332,171 datagrams and reported 58
  local socket drops. This exercised the current direct xVeil path with
  contact consent in place at the start of bulk traffic.
- ogate reuses its TUN read allocation between packets that are copied
  into batches. It hands the allocation to the IPC writer for a raw
  packet. Each successful read exposes only its zeroed IPC prefix and
  the current packet.
- In a Linux TCP comparison, two senders offered 32 Mb/s each through
  the same hub, and exchanged the old and new ogate binaries for the
  second warm sample. Together the warm samples delivered all 334,551
  UDP datagrams and all 400 SDK chat messages. The summed sender CPU
  across the two roughly 23-second windows per build was 1.60 s before
  buffer reuse and 1.51 s after it. Warm chat p99 was at most 3.07 ms.
  During the first burst, the new and old sender respectively lost
  5,469 of 82,613 and 4,564 of 82,374 datagrams. Cold loss remains open.
- The same ogate passed real TUN traffic both ways with an older daemon
  and batching disabled. The current daemon's gateway withdrew the
  route 0.878 s after the old daemon disconnected.
- Two experiments gave ready TUN reads priority for up to eight packets
  after a batch deadline. With an immediate timer at the nominal
  deadline, IPC requests for the first 40,000 UDP datagrams grew from
  7,416 to 13,016 and job refusals from 2,992 to 3,827. Both runs used
  the same 200 µs setting, 24 gateways and two 32 Mb/s TCP-backed flows.
- With the existing timer, it took 6,322 IPC requests versus 6,925 in
  the paired control for the same first 40,000 datagrams. Cold UDP loss
  rose from 8,704 of 164,778 to 15,889 of 162,226. Chat p99 towards the
  hub rose from 533 to 768 ms, with all 200 messages delivered in both
  runs. The bridge retains its original scheduling.
- The IPC loop constructs and clones the send-handler context after
  accepting its rate, job and byte budgets. Rejected sends skip these
  clones. The handler still uses the timestamp captured before the
  budget checks to calculate its deadline.
- In the first 24-gateway Linux TCP pair with that change, the same
  ogate binary carried two 32 Mb/s UDP flows. The control lost 1,629
  of 166,154 datagrams. The deferred-context daemon lost 3,849 of
  166,710. The source IPC refusals accounted for 1,555 and 3,464 missing
  datagrams respectively. Receiving sockets counted the remaining 74
  and 385. Both runs delivered all 200 SDK chat messages. Chat p99
  towards the hub was 182 ms on the control and 402 ms with the change.
- The reverse-order pair lost 13,363 of 164,627 datagrams on the
  control and 9,241 of 164,932 with the change. It delivered all 200
  chat messages in both trials, with p99 towards the hub of 401 and
  391 ms respectively. Total sender daemon CPU moved from 4.52 to
  4.99 s in the first pair and from 4.83 to 4.31 s in the repeat. The
  differences in loss, latency and CPU changed direction between pairs.
- Queue, rate and local source rejections use a contiguous stack buffer
  for the two-byte send error. `SERVER_BUSY` writes the header and the
  code through one `write_all` call. The bytes and request ID match the
  existing IPC response format. Rate and source-identity errors retain
  their legacy zero request ID.
- An IPC prototype borrowed the destination and data length from the
  frame before taking a destination slot, leaving payload decoding to
  the handler. In a macOS ARM64 process-local comparison, the median
  cost of that step fell from 56.9 to 2.4 ns for 1,200 data bytes and
  from 215.1 to 2.4 ns for 12,000 bytes. The decoder tests included
  pre-reply-channel sends and truncated frames.
- Two cold Linux ARM64 pairs used the same ogate, 24 gateways, 4,096
  entries per gateway and two 32 Mb/s UDP flows over TCP. In the first
  pair the control lost 12,670 of 165,326 datagrams and the prototype
  lost 20,747 of 164,836. With the order reversed the control lost
  13,090 of 165,749 and the prototype lost 5,160 of 164,442. Source IPC
  job rejections accounted for 12,429 and 20,689 losses in the first
  pair, and 12,903 and 4,867 in the second. Receiving sockets accounted
  for the remaining losses in all four trials.
- Each trial delivered all 200 SDK chat messages. The p99 towards the
  hub rose from 617 to 633 ms and from 356 to 433 ms in the two pairs.
  On both senders in each trial, receive-window-limited time increased
  and send-buffer-limited time stayed flat. A mixed run with the
  pre-batch daemon passed raw TUN traffic both ways and delivered all
  48 SDK chat messages exactly once. The prototype was set aside after
  the inconsistent UDP results and the higher chat p99 in both pairs.
- An ordered session reader prototype appended body bytes directly to
  pooled capacity after validating the header and reserving the global
  body budget. The initialized length retained progress across
  cancellation. The same frame length and deadlines bounded reads. A
  macOS ARM64 in-memory comparison measured 525 to 408 ns per 12,000-byte
  body and 1,108 to 823 ns per 61,440-byte body. Both readers took about
  246 ns at 1,200 bytes.
- On Linux ARM64, two pairs used 24 gateways, 4,096 entries each and two
  32 Mb/s UDP flows over TCP. Cold losses increased from 10,221 of
  165,607 datagrams to 16,718 of 164,020 in the first pair, and from
  26,376 of 161,596 to 28,551 of 161,144 with the order reversed. IPC
  job rejections accounted for 10,128, 16,541, 26,122 and 28,504 losses.
  UDP receive socket drops accounted for the rest. Each trial delivered
  all 200 SDK chat messages. Cold p99 towards the hub increased from
  312 to 770 ms and from 566 to 1,345 ms. The prototype was set aside.
- The four warm repeats delivered all 669,103 UDP datagrams. The hub
  daemon's thread runnable wait totaled 10.90–20.14 s across threads per
  cold sample and 2.38–3.49 s per warm sample. Peak TCP receive queues
  ranged from 1.09 to 2.14 MB in the cold samples and from 10 to 42 kB
  in the warm samples. Each warm repeat delivered all 200 SDK messages
  with p99 below 1.25 ms. The prototype also passed raw TUN traffic both
  ways with a pre-batch daemon and delivered all 48 SDK messages.
- A cold Linux test kept the binaries fixed and changed the hub
  container's cgroup CPU weight from 100 to 532 on the two-vCPU stand.
  Hub thread runnable wait fell from 13.13 to 5.58 s and the peak TCP
  receive queue fell from 1.79 MB to 104 kB. UDP losses fell from 7,234
  to 60, with 7,232 and 60 respectively matching IPC job refusals. The
  weighted trial sent 151,221 datagrams versus 165,447 in the control
  at the same configured rates. Both delivered all 200 SDK messages.
  Chat p99 changed from 482 to 144 ms towards the hub and from 116 to
  183 ms in the opposite direction.
- A reverse-order repeat used 32 Mb/s per flow with weight 532 and
  29 Mb/s per flow with weight 100 to compensate for the first pair's
  difference in actual offered load. Both delivered every datagram,
  161,079 and 151,400 respectively. Peak hub TCP receive queues were
  88 and 155 kB, and runnable wait totaled 3.54 and 6.00 s. Both
  delivered all 200 SDK chat messages. The weighted run measured chat
  p99 of 20 and 26 ms versus about 3 ms in both directions at the lower
  rate. These samples leave the chat latency cost at equal offered load
  open.
- Another pair fixed the offer at 83,636 datagrams per flow over 23 s.
  Both runs delivered all 167,272 UDP datagrams and all 200 SDK chat
  messages. In aligned one-second windows the send counts differed by
  at most two packets per flow. At 100 ms resolution the largest gap
  was 74 packets. CPU weight 532 moved the hub's runnable
  wait from 5.77 to 2.65 s and peak TCP receive queue from 33 to 11 kB.
  Chat p99 fell from 7.59 to 1.02 ms towards the hub and from 6.59 to
  2.03 ms in the other direction.
- An equal-count repeat in reverse order exposed a traffic-generator
  mismatch. One sender in the weighted run started 205 ms after the
  scheduled epoch and caught up with up to 828 packets per 100 ms. The
  same flow peaked at 376 packets per 100 ms in the control. The two
  weighted flows sent 9,867 packets at least 15 ms late, compared with
  zero in the control.
  The weighted run lost 8,197 datagrams, of which 7,603 matched IPC
  refusals. The control delivered all datagrams. These measurements
  capture source scheduling pressure and unequal burst timing.
- A separate pair waited for both senders to arm and launched an
  additional CPU worker at the common start. It stayed runnable for
  eight seconds with the same 0.70 CPU quota in both runs and received
  3.54 CPU-seconds at hub weight 100 and 2.92 at weight 532. Both
  sender pairs started within 0.06 ms of each other and sent exactly
  167,272 datagrams in 23 s. UDP losses fell from 23,945 to 17,611,
  with 23,927 and 17,553 matching IPC refusals. The hub's runnable wait
  fell from 18.71 to 5.25 s and its peak TCP receive queue from 985 to
  82 kB. All 200 SDK messages arrived in each trial. Chat p99 fell
  from 283 to 86 ms towards the hub and from 171 to 41 ms in return.
- Higher hub weight increased sender lateness in the CPU contention
  pair. For the two flows combined, the number of datagrams sent at
  least 15 ms after their schedule rose from 1,349 to 16,579. The
  largest per-flow 100 ms count went from 418 to 531. This confirms
  the need to measure sender timing as well as the hub receive queue
  when qualifying scheduler weights on a shared host.
- A separate cold start ran the first end-to-end probes in groups of
  four before opening the UDP flows. All 24 paths answered in 12.52 s.
  The following 38 s sample lost 76 of 137,175 UDP datagrams, with one
  loss in the first eight seconds. Session TX drops still occurred,
  including during periods with little UDP loss. Both TUN taps and the
  receive socket again recorded zero capture or socket drops.
- With a pre-batch daemon and a 34-entry table, the new bridge passed
  traffic in both directions and withdrew the route 4.33 s after the
  old daemon reported the disconnect through its single-peer query.
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

#### xVeil text delivery on a shared gateway

- A two-vCPU Linux ARM64 hub served 24 gateways with disjoint 4,096-entry
  tables and 48 authenticated sessions. Two xVeil test clients on macOS
  used the verified `94babde1` FFI build and connected to the real hub
  and one spoke. The test accepted contacts before load and used xVeil's
  text, persistence, and delivery-confirmation paths. It observed each
  message through the application store with a 50 ms polling interval.
- Two 32 Mb/s UDP flows used the same start epoch and sent exactly
  167,272 datagrams per trial over 23 s. An additional CPU worker had
  the same 0.70 CPU quota for eight seconds and received 5.59–5.61 CPU-s.
  The trials ran TCP, QUIC, QUIC, TCP with the same daemon and ogate
  builds. All tunnel datagrams arrived, and xVeil delivered all 96
  messages exactly once and confirmed each submission in every trial.
- Application-observed delivery p95 was 58 ms for both TCP trials and
  56–58 ms for QUIC. Confirmation p95 was 61–62 ms for TCP and 63–65 ms
  for QUIC. In the same samples, the hub daemon used 3.99–4.05 CPU-s
  with TCP and 5.07–5.12 CPU-s with QUIC. These measurements describe
  one shared Linux host at 64 Mb/s of total tunnel traffic.
- At two 64 Mb/s flows, both transports sent 334,546 UDP datagrams in
  23 s. TCP lost 25,326 and QUIC lost 37,918. xVeil delivered and
  confirmed all 96 messages in both runs. Delivery p95 rose to 1.02 s
  with TCP and 3.12 s with QUIC, and confirmation p95 to 1.23 s and
  3.30 s. Most of the delivery delay was in the spoke-to-hub direction,
  which shared the transport with one of the two UDP flows.
- The higher-rate pair had the same packet count and start schedule.
  Senders ran at least 15 ms late for 660 TCP and 6,637 QUIC datagrams.
  Peak source bursts were 793–818 and 933–1,046 datagrams per 100 ms,
  respectively. These differences in actual offer timing limit what the
  single higher-rate pair establishes about the transport choice.
- A TCP-only follow-up at 128 Mb/s compared the 200 and 1,600 µs batch
  windows on the two sending gateways in both orders. Each run first
  sent 26 sparse tunnel pings on each measured path, then offered
  334,546 datagrams with concurrent xVeil text traffic. The 200 µs runs
  lost 2,365 and 2,248 datagrams. The 1,600 µs runs lost 4,044 and
  3,579. The source IPC job counters registered 245–264 refusals at
  200 µs and 324–369 at 1,600 µs. Each run delivered and confirmed all
  96 xVeil messages.
- Confirmation p95 went from 305 to 190 ms in the first pair and from
  542 to 376 ms in the reverse pair. Delivery p95 went from 114 to
  129 ms and from 332 to 182 ms. Before load, median ping RTT across the
  paths ranged from 4.44 to 7.35 ms at 200 µs and 5.87 to 6.90 ms at
  1,600 µs. Under load, the larger window raised ping p95 on both paths
  in the first pair and lowered it on both paths in the reverse pair.
- The gateway now reloads `batch.flush_after_us` on SIGHUP. Each open
  batch keeps the deadline assigned to its first packet. Before sending
  it, ogate still checks the current route and admission. On Linux, a
  signed gateway and a manual gateway with a pre-batch daemon peer both
  switched from 200 to 32,000 µs and back on the same TUN and TCP
  connection. Each completed 160 numbered round trips. An out-of-range
  value left the previous window active. Applying a manual route removal
  together with a window change withdrew the route on the same TUN.
- A further signed run used `ogate reload --pid` during the tunnel
  exchange and an SDK chat on the same daemon sessions. All 160 TCP
  round trips and all 96 SDK messages arrived without duplicates.

#### Batch scheduling with many destinations

- The egress loop caches the next batch deadline. Opening a batch can
  advance it and removing the earliest batch allows the next lookup to
  recompute it. A timer drain records the next remaining deadline during
  its existing walk. Each batch keeps the deadline chosen at first push.
- A macOS ARM64 replay alternated both implementations with 24, 256,
  and 4,096 pending peers. Append plus deadline lookup took 35–41 ns
  with 24 peers, versus 59–60 ns before. With 256 peers it took
  90–92 ns, versus 290–310 ns. With 4,096 it took 1.43–1.44 µs,
  versus approximately 5.70 µs. This measures scheduling in memory.
- In four Linux runs, one TUN had 24 active peers with 4,096 configured
  routes. Both gateways used an 8 ms batch window and delivered all
  76,800 datagrams per run. The hub ogate used 0.39–0.41 CPU-s before
  and 0.42–0.45 CPU-s with the cache during the eight-second send window.
  These runs did not establish a reduction in total gateway CPU.
- With 48 active peers, the two previous-build runs and one cache run
  each delivered all 153,600 datagrams. They used 0.51–0.52 CPU-s on the
  hub ogate. The other cache run delivered 150,386 datagrams and had
  2,569 sends more than 5 ms behind schedule. The three complete
  workloads had zero such late sends.

### Sustained Linux load

- The stand uses two Linux ARM64 vCPUs, 14 nodes, and a 217,260-byte
  signed policy with 4,096 assignments. One node runs the previous
  daemon, and three policy stores have recovery enrolled. Two paced UDP
  flows offer 16 Mb/s each, with one persistent TCP flow offering about
  8 Mb/s. Mirrors poll normally during the load.
- In the first run, the 13 subscribers installed revisions 2 and 3
  within 14.06 s and 13.35 s respectively. After restarting one
  subscriber's daemon, the restarted daemon opened a private session
  about 5 s after launch. The two ogate processes needed subsequent
  full admission sweeps, and the tunnel missed the 18 s recovery probe.
- Signed mode now remembers recently verified peer IDs as query hints
  for 30 s, including across a daemon reconnect. A bounded round-robin
  retry uses the existing per-connection pace at most once per second
  while the normal sweep continues. A new binding still starts with
  no admitted routes. Each retry requires a fresh positive daemon reply.
- In the next run, the restarted daemon's tunnel answered 1.47 s after
  launch with the original ogate process and TUN interface. The same
  node then missed the next policy update. Its mirror stream opens were
  repeatedly refused after the restart, while the other 12 subscribers
  installed the revision. This run isolated a separate APP stream
  teardown problem.
- A ten-minute run with route retries reproduced nine refused mirror
  opens on the restarted daemon. It missed revisions 4 and 5 and
  received revision 6. Address withdrawal, restoration, and the ban
  checks still ran. The unaffected TCP flow stayed connected and
  delivered 599.9 MB at 8.00 Mb/s.
- An inbound APP stream's accepting endpoint now owns its dispatcher
  entry. The entry is released after local close or if the endpoint
  cannot accept the open. A delayed cleanup can release only its own
  entry, even if the same peer reuses the wire ID after restarting.
  OVL1 and IPC frame formats are unchanged.
- With both fixes, all seven rollouts reached the eligible subscribers
  in at most 14.97 s. They included withdrawal and restoration of a
  virtual address, verified end to end after 17.20 s and 17.36 s from
  publication. The restarted daemon's tunnel answered 1.47 s after
  launch and its next mirror update succeeded. After a separate daemon
  stall the tunnel answered 0.14 s after resume. The ban blocked both
  directions by the 2.15 s probe and held through two later revisions.
- The final run lasted 600 s. The restarted subscriber recorded zero
  refused mirror opens. The unaffected TCP connection delivered 600 MB
  at 8.00 Mb/s. The two UDP flows sent about 15.99 Mb/s each and lost
  412 of 1,090,463 packets and 77 of 1,090,501 packets respectively.
  The independent ICMP probe received 5,953 of 5,960 replies, with
  p95 of 5.25 ms and p99 of 6.32 ms. The four measured TUN interfaces
  reported zero kernel drops.
- The containers used about 81–101% of one CPU core and 340–384 MiB in
  the samples, including the traffic generators. The publisher's ogate
  and daemon averaged 6.05% and 29.80% of one core over the process
  sampling interval, including their data traffic. A separate macOS
  loopback run of the final daemon and Veil v0.11.59 delivered 1,000
  SDK chat messages in each direction.

### Local IPC rebinding after daemon restart

- The Unix gateway checks for a new local socket every 250 ms while
  waiting to rebind. A replacement can advance the attempt. An
  unchanged socket still uses exponential backoff. Rebinding checks
  the daemon identity, app endpoint, and configured policy authority
  before route reconciliation starts.
- A three-node Linux ARM64 comparison used 4,096 configured routes,
  the same daemon binaries, and an outage of at least 4.4 s. With
  controls based on `a5b28165`, rebinding took 1.37 and 1.42 s from
  the stand's observation of the ready socket. The updated gateway
  took 0.305 and 0.303 s. All four runs restored bidirectional traffic
  on the original gateway processes and TUN interfaces. Each run and
  a separate run with a pre-batch daemon delivered all 48 SDK chat
  messages sent before the restart.
- In four Linux ARM64 runs with a pre-batch local daemon and 128
  configured peers, the first admission sweep took about 16.3–16.5 s.
  After restarting that daemon, the gateway with a recent hint
  published the returning route in 2.28 s after observed readmission
  in both runs. Controls based on `c97ce213` took 16.38 and 16.45 s.
  Bidirectional TUN traffic returned in 2.52 s compared with
  16.63–16.70 s. All runs kept the same gateway process and TUN
  interfaces, and each delivered all 48 SDK messages sent before
  the disconnect. A separate run with the current daemon and 4,096
  configured peers published the route in 0.32 s and restored
  bidirectional traffic in 0.56 s after observed readmission.
  All 48 SDK messages arrived exactly once in that run as well.
- The pre-batch admission path can use the daemon's existing PEERS
  reply once at status connection startup. It checks the prioritized
  prefix with the ordinary single-peer queries and publishes that
  group's results before checking the rest of the table. An empty or
  unavailable snapshot falls back to the configured sweep, with
  recent route hints when available. The same pace and current
  admission checks apply.
- In alternating Linux ARM64 runs with the pre-batch daemon and 128
  configured peers, the first route appeared 0.433 and 0.437 s after
  launching the gateway, versus 16.40 and 16.62 s with controls
  based on `2ec6e789`. Bidirectional recovery after observed
  readmission took 0.56–0.61 s versus 2.50–2.51 s. With 4,096
  configured peers, a pre-batch run published the first route in
  0.427 s and recovered in 0.55 s. A current-daemon run took 0.420
  and 0.55 s respectively. Every run kept its gateway process and
  TUN interfaces and delivered all 48 SDK messages exactly once.

### Remote session changes with pre-batch daemons

- The gateway listens for session changes on pre-batch daemons as
  well. Between groups of the ordinary sweep, a session change can
  trigger a bounded peer snapshot or a check of installed or recently
  admitted routes. Each priority round checks up to four peers through
  the existing single-peer admission query, paced at 125 ms per
  request. Installing a route still requires confirmed admission.
  The ordinary sweep resumes from its previous position.
- In alternating Linux ARM64 runs with 128 configured peers and one
  late-joining peer, the updated gateway installed the route in
  4.13–4.17 s, withdrew it in 0.04–2.26 s, and restored it in
  2.24–4.14 s. Controls based on `4cdaa0e3` took 13.99–14.09 s,
  6.14–6.36 s, and 16.04–16.26 s respectively. Times start when
  the stand observes the session state change through the daemon IPC.
  A pre-batch run with 4,096 configured peers took 4.14 s, 2.20 s,
  and 4.22 s respectively. A run with the current daemon and the same
  number of configured peers took 0.57 s, 0.33 s, and 0.03 s.
  All six runs restored bidirectional traffic on the same gateway and
  TUN interfaces. Every run delivered its 48 SDK chat messages exactly
  once before the remote disconnect.

### Emulated inter-site link

- Three nodes spanned two emulated sites on one Linux ARM64 host. The
  link between sites had 2 Mb/s in each direction, 60 ms one-way delay
  with 5 ms variation, and 0.3% packet loss. The last subscriber ran the
  previous daemon. Median tunnel RTT was 151 ms across sites and
  6.24 ms within a site with TCP, and 153 ms and 6.36 ms with obfs4 on
  the inter-site hop.
- Under a paced 1 Mb/s UDP flow, the 217,260-byte signed snapshot with
  4,096 assignments reached both subscribers in 16.83 s over TCP and
  21.58 s with obfs4. The local path stayed usable during the partition
  until the signed policy expired. At expiry both directions were
  blocked while the local transport session remained established.
- Restoring the link left the expired routes disabled. A newer signed
  revision restored the original tunnels 30.48 s after publication
  over TCP and 28.85 s with obfs4. The revision floor rejected an older
  signed snapshot that was still within its original validity period.
  An owner-authorized ban crossed the WAN and blocked the local pair in
  both directions by the 33.16 s and 32.83 s probes respectively.
- A separate two-node baseline at 1 Mb/s offered UDP delivered 1,699 of
  1,706 raw datagrams and 950 of 1,706 tunneled datagrams. The tunnel
  reported 1,553 session send queue refusals and zero kernel TUN drops.
  The 0.5 Mb/s run delivered 826 of 854 tunneled datagrams. With emulated
  loss set to zero the 1 Mb/s tunnel still delivered only 953 of 1,706.
- At 0.25 Mb/s, the writer admitted one 3,627-byte `APP_SEND_SEALED`
  frame per 1,100-byte UDP payload in all 115 samples. That length
  matches the existing ratchet format with both ML-KEM fields present
  (1,184 and 1,088 bytes), before the session AEAD tag.
- ogate now accepts a local `[batch].flush_after_us` setting and defaults
  to the original 200 µs interval. With TCP and a receiver on the
  previous ogate, increasing the sender's interval to 24 ms raised
  delivery from 940 to 1,706 of 1,706 datagrams on the same 1 Mb/s
  workload. Session send queue refusals fell from 1,500 to zero, and
  measured session bytes per delivered datagram fell from about 3,646
  to 2,144. Median idle RTT rose from 152.5 ms to 177 ms. The batch
  wire format is unchanged and queued packets still pass the current
  route and admission checks before submission.
- With obfs4, delivery increased from 738 of 1,703 datagrams to all
  1,706, and session send queue refusals fell from 1,878 to zero.
  Median idle RTT rose from 152 ms to 178.5 ms.
- A joiner with the greater node ID established a direct private
  session and delivered 10 of 10 tunnel probes through an inbound-only
  entry point listed solely in `[[bootstrap_peers]]`.

#### Faster recovery after policy expiry

- Subscribers keep the staggered 15 s cadence while a snapshot has ample
  validity. After expiry, they use a 4–6 s interval with a
  per-node offset and a single in-flight round. After a higher
  authenticated revision has reached durable storage, a local
  notification wakes the route updater between admission groups. The
  updater reads the protected store and checks the policy and admissions.
- The subscriber uses the same verified-policy notification to bring its
  pending poll forward when a locally installed revision expires sooner.
  It keeps the minimum spacing between rounds. In two pairs of Linux
  trials, an operator installed a signed policy with three seconds of
  validity immediately after a normal poll. With the primary mirror
  offline, the secondary supplied the newer 4,096-assignment revision.
  Bidirectional traffic on the original TUN returned 4.56 and 5.39 s
  after expiry with the update, versus 12.15 and 12.26 s in the control.
  All four trials blocked the expired routes while the private session
  stayed active.
- The same three nodes ran two control and two candidate trials, with
  the previous daemon at the last subscriber. The TCP link between
  sites retained its 2 Mb/s, 60 ms one-way delay and 0.3% loss settings.
  The last subscriber received the 217,260-byte policy after 23.84 s
  and 24.07 s with the control and after 8.49 s and 8.55 s with the
  candidate. All tunnel probes recovered after 27.74 s and 27.68 s
  with the control and after 9.12 s and 9.13 s with the candidate.
  Each trial blocked expired routes while the transport was connected.
  The new revision restored the existing ogate processes and TUN
  interfaces, and the durable revision floor rejected rollback.
- In the obfs4 partition run, the last subscriber stored the signed
  policy after 18.35 s while the inter-site link carried UDP load.
  The local pair forwarded from the cached policy during the outage
  until expiry. Link restoration left the expired routes closed.
  Publishing a current revision restored the original interfaces in
  17.80 s. The later remote ban blocked the local pair in both
  directions by the 24.39 s probe.
- On a separate two-vCPU Linux stand, 32 subscribers resumed
  simultaneously with expired snapshots and existing daemon sessions.
  All installed the identical 217,260-byte revision within 0.917 s
  of resume, with p95 of 0.902 s. The publisher verified requests in
  groups of 1 and 31. Subsequent TUN probes succeeded for all 32.

#### Applying a received revocation

- A private node applies a signed ban when its DHT accepts the record
  after verifying the owner, administrator and ban key. Startup and
  periodic scans also apply verified records from the local store.
  The publisher and receiver retire active session senders. Session
  registration checks the same ban list under the registry lock.
  An authorized permanent revocation replaces a temporary ban and
  subsequent automatic bans preserve the permanent entry.
- The three-node emulated WAN used the previous daemon at the
  publisher and the revoked node. With TCP, the control receiver
  applied the revocation 48.83 s after publication began and the
  revoked peer received UDP traffic for 4.34 s after that event.
  Applying the record on receipt alone reduced the first delay to
  0.37 s and exposed a 4.94 s residual egress window. With retirement
  enabled, the receiver applied the ban in 0.35 s and the last UDP
  delivery in either direction preceded the event by about 13 ms.
  The unrevoked inter-site path remained reachable. A restart restored
  the signed revocation from the DHT snapshot.
- With obfs4 on the inter-site hop, the receiver applied the signed
  ban in 0.22 s after a daemon configuration reload. The last UDP
  delivery in either direction preceded the event by about 4 ms.
  The receiver restored the revocation again after a restart.
  A separate public-mode macOS loopback test with the previous daemon
  delivered 1,000 SDK chat messages in each direction.

#### Enforcing revocations on relayed application datagrams

- A private node consults its local revocation list before routing a
  new addressed application datagram and after asynchronous route or
  key resolution. Relays check the addressed recipient. At the
  destination, delivery checks the sender and any verified signing
  device before handing the datagram to the application.
- Nodes on separate isolated Linux bridge networks exchanged SDK
  messages through a common relay in both directions. After the
  publisher revoked one endpoint and the sending site applied the
  record, the revoked endpoint received none of the three new probe
  datagrams. In a four-node repeat, the two unrevoked endpoints
  continued to exchange messages across the same relay after the ban.
  A separate WAN check retained direct-session retirement and
  restored the signed revocation after restart. The macOS SDK chat test
  with the previous daemon again delivered 1,000 messages each way.

#### Cancelling acknowledged retries after revocation

- The pending ACK tracker uses the private network's current ban list.
  It releases the revoked recipient's entries and byte budget on the
  next tick, including batches already waiting on relay capacity. The
  origin receives the existing IPC delivery-failure event. A local
  revocation contributes zero losses to the relay's score.
- Both single-frame and batch retries recheck admission before sending.
  A batch also checks immediately before polling asynchronous queue
  admission. A regression test releases relay capacity just after
  revocation and before the timer has removed the pending entry. The
  retry sends zero frames and the relay can accept unrelated traffic.
- On a three-node Linux stand with separate bridge networks, the
  relay accepted two acknowledged sends while its egress to the
  destination was held. The sender learned a signed revocation and
  the application received two failure notifications 0.79 s after it
  began the sends. The sender recorded zero retries through the
  original five-second timeout and retained its session with the relay.
- A healthy relay run exposed a delivery receipt gap. The destination
  received the datagram once and the sender retried after five seconds
  because the destination had no direct session back to it.

#### Returning delivery receipts through P-Net relays

- Encrypted acknowledged `Forward` messages can return receipts through
  the ordinary authenticated private-network sessions used on the way
  out. Relays retain the content ID, admitted downstream peer and previous
  peer for at most 30 seconds in a cache capped at 4,096 entries per node.
  A valid carrier chunk uses the original message ID. Revoked peers and
  expired envelopes are ineligible for receipt return.
- Direct confirmations keep their existing format. The relayed status
  uses its own MAC domain and stays within the existing `DeliveryStatus`
  frame. The origin checks the recipient's MAC, consumes the pending entry
  once and reports the usual `DELIVERED` IPC stage. Legacy peers ignore
  the new status. Returning a receipt across the entire path requires
  upgraded participants when no direct return session is available.
- On separate Linux bridge networks, 32-byte and 150,000-byte payloads
  reached the recipient once and both receipts returned through one and
  two relays. The larger message was reassembled from carrier chunks.
  The sender logged zero retransmits after the five-second timeout.
- Deployments with a previous daemon at the origin or at the relay
  continued to deliver application messages. A mixed-version macOS SDK
  chat session delivered 1,000 messages in each direction.
- A new last hop can return a cached receipt for a completed chunked
  transfer after carrying the original 16-byte authentication tag. When
  the tag spans several chunks, all pieces must arrive from the same
  authenticated neighbor. The recipient matches the proof to the transfer
  it already decrypted. It retains a tag hash and bounded partial tags
  for this check. Retries use the existing wire format.
- On a four-node Linux stand, the first receipt for a 150,000-byte message
  was blocked and the original relay stopped. The sender received the
  receipt through a backup relay after one retry, 5.8 seconds after the
  send. The application received the payload once. The previous daemon
  also delivered the payload once and made two retries without a receipt.
- On a shared downstream link, a relay can change the return path after
  a new authenticated upstream admits the same complete indexed batch.
  The relay compares a digest of the forwarded ciphertext and framing.
  It retains one receipt from the matched downstream, two candidate
  upstreams and up to eight out-of-order chunk digests per tracked pass.
  A matching batch can return the retained receipt even when the old
  local queue accepted it and the return path failed farther upstream.
- In a five-node Linux test, a 150,000-byte message crossed the same final
  link before and after failover. The previous daemon delivered the data
  once and made two retries without a receipt. The updated relay returned
  the receipt on the first retry after about 5.7 seconds. In a second run,
  the old relay stayed connected to the shared relay and lost its link to
  the origin. The shared relay returned the original receipt after the
  same batch arrived through the backup. Packet filtering blocked fresh
  receipts during the retry, and frame fingerprints confirmed the reuse.
- A mixed-version run confirmed the receipt on the first retry with
  only the shared relay upgraded. In a separate run the old sender's
  retry tracker kept the failed first hop for both retries while ordinary
  datagrams already passed through the backup.
- A private sender with a keyed receipt now derives the original content
  ID from the indexed ciphertext, its addressing and a random transfer ID.
  A chunk header flag advertises this use of the existing ID. A shared
  relay can check a complete retry against the ID even if it initially
  forwarded just one chunk. On first reassembly the upgraded terminal
  checks the commitment before opening the ciphertext and creating a
  receipt. The origin still checks the receiver's end-to-end receipt MAC.
- Older receivers ignore the new flag and still reassemble the same frame
  layout. With an older sender's random content ID, the relay continues to
  use its original full-batch comparison. The partial-link recovery needs
  an updated sender and shared relay.
- A deterministic dispatcher test delivered the earlier chunks through a
  second path and only the final chunk over the shared link. On a complete
  retry, the shared relay returned the original keyed receipt through the
  new upstream and the application saw one delivery. Altered retries and
  fragments supplied by different peers could not move the return path.
- A four-node Linux stand confirmed 150,000-byte sends through a backup
  relay on the first retry in about 5.6 to 5.8 seconds. Each run delivered
  once. The stand covered all updated nodes, an updated sender with old
  relays and receiver, and an old sender with updated relays and receiver.

#### Recovering acknowledged sends after the first hop disappears

- A P-Net sender checks live sessions when the original first hop cannot
  take the retry. A send with an end-to-end receipt key can use the same
  live relay candidates as an ordinary sealed send, even when its route
  cache has no backup. Retries without that key stay on known routes.
- Admission rechecks recipient and relay revocations, including after a
  chunk batch has waited for capacity. It respects the destination's
  pinned instance. A chunk batch still waits for credits on a full queue.
  Legacy public retries retain their cached path.
- On a four-node Linux stand, the original relay stopped and an
  authenticated backup session became available. The sender's cache had
  no route through the backup. The old daemon failed to receive a receipt
  after two retries for either 32 or 150,000 bytes. The updated sender
  confirmed both sizes on their first retries after about 5.8 seconds.
  The destination delivered each message to the application once.

#### Confirming local application admission

- An acknowledged, encrypted P-Net Forward reserves a slot in the
  destination application queue before opening the ciphertext. A busy or
  absent endpoint leaves the ratchet unchanged and allows the sender's
  existing retry to try again. Completed chunk reassembly can reopen for
  that retry without retaining plaintext.
- The recipient creates a delivery receipt only after enqueueing to the
  same live endpoint registration. That receipt confirms queue admission.
  A registration that closes during decryption causes a delivery failure
  with no receipt. The receiver can still replay a cached receipt for an
  already admitted message while its application queue is full.
- On the Linux IPC stand, an application unbound its endpoint before a
  150,000-byte send and rebound it after the first arrival. The previous
  daemon returned a receipt in 5 ms, with zero application deliveries.
  The updated recipient delivered once after rebinding and confirmed the
  first retry after 5.5 to 5.8 seconds. The mixed run upgraded only the
  recipient. A dispatcher test also covered a full queue with single and
  chunked ratchet ciphertexts.

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
- Measure update convergence and tunnel throughput with many simultaneously
  active subscribers. Define owner-key rotation and recovery on the configured
  trust anchor before broader rollout.

### Signed snapshot implementation and checks

- `veil-cli network route-policy` signs TOML input, verifies the current
  snapshot, and installs or reports the revision in an owner-only Unix
  state directory. The store is serialized across processes. Acceptance
  waits for both the snapshot and directory to be synced.
- macOS CLI processes exercised real signatures, authorization to the
  pinned network and owner, tampering, revision conflicts, and rollback
  after expiry and reopening. The store refused a macOS extended ACL
  grant on an otherwise owner-only directory. Linux and macOS unit tests
  cover the same signed format, concurrent updates, and unsafe state.
- ogate reuses signature verification and parsed assignments when the
  protected store contains the exact same signed bytes under its pinned
  owner. Every read still checks the directory, lock and snapshot file,
  decodes the recovery envelope, and syncs the directory. Changed bytes
  go through signature and revision checks. Mirrors share the verified
  bytes between concurrent responses. A macOS ARM64 comparison with
  Ed25519 measured 524.7 to 77.5 µs per protected reload for a
  217,260-byte snapshot with 4,096 assignments, and 75.0 to 47.5 µs for
  one assignment. On Linux, a gateway with that snapshot already cached
  withdrew its routes when the snapshot file became group-readable.
  Restoring owner-only permissions restored bidirectional traffic on
  the same TUN interface.
- Mirror downloads are authenticated on a blocking worker. The verified
  offer owns its exact signed bytes and is bound to the network and
  pinned owner. On acceptance the store checks the validity window and
  current disk revision under its lock. It returns the durable bytes,
  including the existing signature when an equal policy is re-signed.
  The gateway then uses those bytes in its protected reload cache.
- In a macOS ARM64 store comparison with 4,096 assignments and Ed25519,
  median time for verifying an offer, committing a new revision and
  rereading it went from 10.264 to 9.198 ms. This included the same file
  and directory durability barriers in both paths.
- Signed-mode ogate obtains a local IPC witness from the daemon's active
  private gate. The daemon verifies its local membership before
  advertising the network ID, owner algorithm and public-key fingerprint.
  The data and status connections must confirm the same authority; the
  packet path enforces policy and membership deadlines. Ordinary SDK
  clients retain their existing HELLO body and manual mode remains available.
- An isolated Linux TUN pair passed traffic with an installed signed
  snapshot and empty manual peer lists. Installation of a higher
  revision removed a peer in both directions and a later revision
  restored traffic. An older daemon was refused before TUN creation
  in signed mode.
- The same-ID daemon with another owner was refused on reconnect.
  Restarting the original daemon restored traffic through the same
  ogate process and TUN interface. At policy expiry traffic stopped
  while the TCP session was still established.
- A higher revision with a changed local TUN address withdrew the
  previous routes until a matching revision was installed. After an
  admin ban removed the route, a newer owner-signed assignment still
  could not readmit the banned peer.
- The same bridge binary also passed bidirectional manual-mode TUN
  traffic with mixed old and new daemons. The FreeBSD ogate cross-check
  passed; signed-mode packet forwarding was qualified on Linux.

### Automatic delivery implementation

- Explicitly configured mirror devices serve installed snapshots over direct
  private Veil application streams. First installation still uses the local
  CLI with the pinned owner. Publishers need only the signed snapshot.
- Both sides check live P-Net admission. The receiver verifies the signed
  bytes and installs through the same persistent revision floor as the CLI.
  A current member whose virtual address was withdrawn can receive the
  withdrawal and later renewals. Receivers with expired snapshots can
  recover while their daemon membership is current.
- Receivers stagger their polls and check all configured active mirrors.
  Equal highest revisions with differing valid contents in one poll leave
  the installed revision in force. Unchanged snapshots send only a length
  frame; large downloads and simultaneous requests have fixed bounds.
- A subscriber watches for admitted-session events on its local polling
  connection. An event can advance the next poll, with a per-node delay
  and 4–6 s minimum spacing. It leaves the ordinary deadline in place
  and permits a single in-flight round. Each poll checks all configured
  mirrors and revalidates their admission and the signed offers.
- Failed subscriber IPC connections retry on the same staggered 4–6 s
  cadence. Reconnecting can trigger one early poll under the same
  spacing rule, including when the daemon admitted a mirror while the
  subscriber was disconnected.
- In two pairs of Linux trials, an IPC proxy refused new local connections
  after the initial poll. The private daemon admitted the secondary mirror
  while the subscriber could not reconnect. Once the proxy allowed new
  connections, the previous subscriber installed the 4,096-entry policy
  after 14.66 and 14.85 s. The updated subscriber installed it after 6.40
  and 6.34 s. All runs passed traffic both ways on the original TUN while
  the primary mirror stayed offline.

- An isolated Linux pair recovered bidirectional TUN traffic after the
  subscriber's original snapshot expired. It fetched the full 217,260-byte
  signed snapshot with 4,096 assignments and stored the exact signed bytes.
- An isolated three-node run refused conflicting snapshots at the highest
  revision, accepted a later revision, and continued receiving updates through
  the secondary mirror after the primary stopped.
- In a three-node Linux comparison, the primary mirror stayed offline
  and the secondary joined just after the subscriber's first poll. On
  the same daemon build, the subscriber installed the 4,096-assignment
  snapshot 14.82 s after session admission with periodic polling and
  4.18 s with the session event. Both passed TUN traffic in both
  directions. The updated gateway also installed a subsequent revision
  and restored traffic on the same TUN interface in 8.50 s after its
  local daemon restarted.
- The updated gateway repeated the conflicting-revision and secondary
  fallback checks. In manual mode with the pre-batch daemon it passed
  raw TUN traffic both ways, delivered all 48 SDK messages exactly once
  and withdrew the route 0.88 s after the daemon reported disconnect.

- In the paired run the mirror propagated address removal, restored access on
  the same TUN, and resumed serving after a daemon restart. A banned member
  stayed on its existing revision. A separate obfs4 run delivered the same
  maximum-size Ed25519 policy and restored TUN traffic after expiry.
- The final bridge also passed manual-mode TUN tests with an older daemon.

### Concurrent mirror requests

- A mirror batches admission queries for up to 64 outstanding requests. It
  loads and verifies the protected snapshot once per admitted group. Each
  stream checks its own admission deadline before writing.
- Incoming remote application streams use distinct local IPC handles.
  The daemon resolves data and closes by authenticated device, wire
  stream ID and endpoint. Replies keep the original wire ID. The internal
  exit proxy also keeps stream state per physical opener.
- On an isolated two-vCPU Linux stand with 20 concurrently resuming
  subscribers, the earlier implementation failed to install revision 2
  within 56 seconds. After fixing stream routing and batching admissions,
  all 20 installed the 217,260-byte policy with 4,096 assignments in
  0.54 seconds. The mirror processed groups of one and nineteen.
- The final build installed identical signed bytes on all 32 simultaneously
  active subscribers in 0.763 seconds. The mirror processed those requests
  in groups of one and thirty-one.
- The exact-byte policy cache passed a repeat with 32 resuming
  subscribers. All installed the same 217,260-byte snapshot within
  0.831 s, with p95 of 0.820 s and mirror batches of one and thirty-one.
  The concurrent tunnel probe received all 416 ICMP replies and the
  paced TCP flow averaged 10.14 Mb/s.
- The verified-offer path passed the same 32-subscriber workload. All
  installed the exact signed snapshot within 0.755 s, with p95 of 0.751 s.
  The publisher again served batches of one and thirty-one. The tunnel
  received all 416 ICMP replies and carried the 10.14 Mb/s paced TCP
  flow. Separate runs preserved conflict rejection and secondary mirror
  recovery, and delivered all 48 SDK messages with the pre-batch daemon.
- A subscriber on the previous build fetched the same maximum-size
  policy from the new mirror over obfs4 after its earlier snapshot expired.
  It kept the installed revision after the mirror banned its device.
- Before preserving unchanged routes, applying the larger snapshot cleared
  active routes for about eight seconds while ogate rechecked admissions.
  The paced TCP probe averaged 7.92 Mb/s and the ICMP probe received 337 of
  413 replies in the 32-subscriber run.

### Signed policy activation

- On a verified policy change, ogate immediately discards routes with
  removed or changed peer addresses. It keeps admissions for identical
  assignments on the same daemon connection until rechecked. Those
  admissions remain subject to the earlier policy and membership deadlines.
  The next sweep rechecks them first in their previous relative order.
- In a repeat of the 32-subscriber Linux test, the existing TUN probe
  received 415 of 416 replies, with a maximum gap of 234 ms at a 100 ms
  probe interval. The paced TCP flow averaged 10.12 Mb/s. The new
  4,096-entry snapshot was installed on all subscribers within 0.87 s.
- A paired Linux test kept one TCP connection open through policy
  expansion on both ends and SIGHUP during the admission sweep. It
  completed 490 round trips with a maximum reply gap of 55 ms. A later
  withdrawal removed the route while the carrier stayed up. Fresh
  admission restored it on the same TUN, and a ban still removed it.
- The final bridge passed the 34-peer manual-mode TUN fixture with the
  daemon that predates admission batches.
- An accepted SIGHUP checks the protected signed policy between
  admission batches. An unchanged policy keeps the sweep cursor. In
  two pairs of Linux trials, the operator installed a 4,096-entry
  snapshot withdrawing one live peer's address during a sweep. The
  updated gateway published the withdrawal 0.43–0.69 s after the reload
  request, compared with 6.32–6.48 s before. All runs blocked tunnel
  probes in both directions while the private session stayed admitted.
  A second peer completed all 160 round trips over one TCP connection
  in each run, and the TUN interface stayed up.

## 4. Provision private entry points

- The opt-in `private_configured` mode uses explicitly configured peers,
  bootstrap peers, and pinned relays for first contact. It verifies the
  local membership certificate before starting network services.
  Public rendezvous, automatic seeds, and caches without a bound network
  authority are skipped. Authenticated private sessions can still use
  DHT and peer exchange to discover additional members.
- Existing configurations retain their discovery behavior. Older daemons
  reject the new configuration enum and can still join the same network
  in their existing `private` mode. Changing the running node's mode or
  trust settings requires a restart.
- On an isolated Linux stand, an unavailable configured entry point left
  the new node waiting without contacting the instrumented fallback
  endpoints. Once the entry point came up, the new node discovered a member
  on the previous daemon through peer exchange and established a direct
  TUN route. A rejected trust change left this route available.
- A separate Linux run placed a signed revocation and an unrelated value
  in the persisted DHT snapshot. The daemon restored the revocation before
  listening and refused the revoked member both after restart and after
  reloading the same trust settings.

## 5. Replace the owner key

- The operator obtains the next owner pin through an independent
  management channel, issues replacement membership certificates, and
  coordinates a restart of the daemon and ogate. The network ID and the
  device identities stay stable. Each daemon verifies certificates
  against one configured owner.
- The policy preflight checks the successor's signature and validity
  window and authenticates the installed snapshot under the current pin.
  Under the existing state lock, the install checks the revision again
  and atomically replaces the snapshot with a newer one. An identical
  retried install succeeds. An expired installed snapshot still supplies
  the revision floor. Only the old public key is required.
- On an isolated three-node Linux stand, all nodes initially passed TUN
  traffic, including a member on the previous daemon. Two nodes rotated
  their pins and certificates after removing the old signing key from
  the test. They resumed bidirectional TUN traffic with the same
  addresses and accepted another new-owner policy. The old member's
  certificate and a higher revision signed by the old owner were refused.
- The operator-managed procedure requires a maintenance window. A staged
  rollout splits the network at the owner pin until both sides have
  installed the new trust settings and re-established their authenticated
  sessions. Configured peers can be waiting in their normal reconnect
  backoff when the second wave comes up.
- An isolated Linux ARM64 stand ran eight TUN gateways, one using the
  previous daemon, with 2,048 entries per signed policy and a signer
  outside the test network. The previous signing key was removed before
  preflight. After the first four gateways rotated, peers under different
  pins refused each other's certificates. The four rotated gateways
  applied a signed address withdrawal and restoration through their
  mirror while the second group kept the previous policy. A 92 s,
  16 Mb/s UDP stream within that group delivered every datagram across
  the first wave in two runs (167,244 and 167,188 datagrams).
- After the second wave restarted, bidirectional probes between the old
  daemon build and a first-wave peer succeeded within 6.20 s. The path
  between the two mirrors recovered in 46.49 s on its next scheduled
  dial. A separate run exceeded the initial 25 s probe deadline.
- The second mirror distributed revision 13 to all eight gateways. With
  its ogate stopped, the first mirror distributed revision 14 to all
  seven running instances in 15.04 s. The returning gateway caught up
  in 4.78 s and distributed revision 15 to all eight in 13.91 s. One
  TCP connection between first-wave gateways carried 239,976,448 bytes
  in 240 s across the second wave and the mirror outage.
- A matched comparison reused the same eight identities, reciprocal
  peer topology and daemon builds, including one previous build. Each
  trial waited 75 s between the starts of the two four-node waves. All
  16 bidirectional paths between waves recovered in 53.85 s when the
  lower node IDs rotated first and 4.40 s when the higher IDs rotated
  first. Timing began once the last daemon in the second wave became
  ready and its ogate was launched. Both trials rejected certificates
  under the other owner and delivered all 100,001 UDP datagrams on an
  unaffected path during the first wave. The order follows the existing
  dialing rule for reciprocal configured peers.

## 6. Recover after owner compromise

- Operators can enroll an independent offline recovery public key in an
  existing protected route policy store. The opt-in store records the
  recovery pin and retired owner fingerprints alongside the signed
  policy and commits them in one atomic update under the store lock.
- Recovery verifies the pre-pinned key's authorization for the exact
  replacement snapshot, current owner, successor and network. A fresh
  owner can start its revision sequence at 1. Subsequent normal updates
  under that owner still require nondecreasing revisions. Neither normal
  rotation nor recovery can reinstate an owner retired since enrollment.
- The policy mirror continues sending the signed snapshot without local
  recovery metadata. The daemon uses the same membership certificate
  format and operator-configured pin. Local CLI and ogate must support
  the enrolled store format, and daemon trust changes still require
  an independent management channel and a restart.
- A store test verifies recovery from the maximum unsigned 64-bit
  revision, an expired prior snapshot, input substitution, retry after
  reopening, rejection of a retired owner, and subsequent normal updates.
- On an isolated three-node Linux stand, two enrolled stores moved from
  revision 9,223,372,036,854,775,807 to a fresh owner's revision 1.
  They resumed TUN traffic with the same addresses, rejected the old
  owner and certificate, and accepted revision 2 through the existing
  mirror protocol. The original authorization could no longer replace
  revision 2. A node on the older daemon rejoined after receiving a
  certificate under the new owner.

## 7. Diagnose gateway admission

- `ogate check` reads local configuration, the protected signed policy
  when enabled, and the daemon's IPC status. An optional peer Node ID
  checks admission for one route or mirror. The diagnostic uses the
  normal owner, network, and local address checks.
- An isolated Linux stand confirmed admission both before and during
  normal TUN operation. The check identified a missing daemon socket,
  absent peer certificate, missing local assignment, expired policy,
  unsafe policy file, mismatched network or owner, and TUN address or
  prefix mismatch. An admitted mirror with zero route assignments
  returned a successful admission. The manual mode check also worked
  against the pre-batch daemon while SDK traffic continued to work.
- `ogate check --mirror` uses the existing policy stream and verifies the
  returned snapshot against the local owner and revision floor. On Linux
  it distinguished peer admission from a disabled mirror service and
  reported an expired mirror snapshot, an older revision, and conflicting
  contents at the same revision. It verified a newer 4,096-assignment
  policy while the local one was expired, leaving the stored bytes
  intact. The check also passed on an established bidirectional TUN and
  when the installed policy omitted the local address assignment.
- In a separate run of the automatic subscriber, the secondary mirror
  restored bidirectional TUN traffic 5.04 s after policy expiry. A mixed
  run with the pre-batch daemon delivered all 48 SDK messages once.
- An optional `[logging].packet_drop_report_secs` setting reports local
  drops by reason with interval counts. On Linux, the aggregated missing
  route counts matched individual packet traces before and after a
  daemon restart on the same TUN. The receiving gateway counted four
  oversized sub-packets individually. A gateway with reporting disabled
  emitted no summary while discarding packets without a route.
