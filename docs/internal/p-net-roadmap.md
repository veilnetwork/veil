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
- A completed chunk transfer can re-issue its cached receipt through
  its recorded previous hop. Replaying the receipt when the retry reaches
  the recipient through a different last hop remains open.

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

- An isolated Linux pair recovered bidirectional TUN traffic after the
  subscriber's original snapshot expired. It fetched the full 217,260-byte
  signed snapshot with 4,096 assignments and stored the exact signed bytes.
- An isolated three-node run refused conflicting snapshots at the highest
  revision, accepted a later revision, and continued receiving updates through
  the secondary mirror after the primary stopped.

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
- The operator-managed procedure requires a maintenance window. Qualify a
  longer multi-node run with packet traffic and policy changes.

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
