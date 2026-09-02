# Changelog

## v0.11.0 — 2026-09-02

**Both meeting points now speak IPv6.** Neither did, and neither said so.

Mainline is two overlays over one key space: BEP 5 carries IPv4, BEP 32 carries
IPv6 in `nodes6` beside `nodes`, with eighteen-byte `values` entries beside the
six-byte ones. Only the first half was implemented, and the consequence was a
filter that quietly threw away every AAAA the public routers publish — two of
the four have one. A host with IPv6 only could not use the layer at all: the
routers resolved, the filter emptied the list, and the layer switched itself
off with "no router resolved". Nothing recorded that as a decision, because it
was not one.

Now: a second UDP socket, both compact formats, `nodes6` read and written, and
`want` asking for contacts of both families. A host without IPv6 binds what it
can and is unaffected.

`want` is part of the message rather than something the encoder adds, and that
matters more than it looks. Adding it unconditionally made this client's bytes
differ from the BEP's own examples — and a client whose bytes differ from the
specification differs from every other client on the wire, which is the one
thing a protocol built to blend in must not do. The round-trip test against
those examples caught it.

Local discovery had the same shape: `LSD_GROUP_V6` has been a public constant
with an encoding test since the layer was written, and nothing ever bound it.
It is bound now, on the same port with the same one-hop scope, and announces
carry their own salt per family so the two datagrams are not linkable to each
other.

## v0.10.7 — 2026-09-02

Four follow-ups from the review of 0.10.5 and 0.10.6, all confirmed against the
code before being taken.

**Choosing a peer slot and claiming it were two separate lock acquisitions.**
The Mainline and Nostr passes run concurrently, so both could see the same slot
free and the loser then dialled on the winner's row — writing a proven identity
against somebody else's address. Selection and reservation are now one critical
section.

**A peer was recorded under the algorithm we assumed rather than the one it
proved.** The handshake knows which signature algorithm was used and dropped it;
everything downstream wrote Ed25519 down as fact. That is not a label: the node
id the direction rule compares derives from the key and its algorithm, so a
mislabelled Falcon or hybrid peer puts the pair back to both ends dialling each
other. The proved algorithm now travels handshake → session → row → cache.

**A window full of tombstones could never admit another peer.** A dial refused
as a duplicate keeps its row on purpose — that is what stops the address being
dialled again — but such a row holds a hash of the address and no key, and
enough aliases for one host would have walled the window off for the life of
the process. A full window may now reclaim the lowest identity-less row; a row
that proved an identity is never taken, because something may be holding that
session.

**And two guards were passing on their own text.** Both read their own source
file to check a call site, and the string they searched for appears in the
assertion itself, so they matched regardless of what the production code did —
the break-check that should have caught it stayed green. They now read the file
with its test module removed.

## v0.10.6 — 2026-09-02

**An inbound connection could end a session that was working.** Two different
questions had one answer: whether an inbound may bypass the directional rule,
and whether it may take the place of a session that is still open. The second
was derived from the first, which is a NEGATIVE list — so every peer source
added after that list was written inherited, silently, the right to displace a
live session. `PeerSource::Rendezvous` arrived that way.

The eviction exists for a real case, and keeps it: a learned peer whose old
link died without either side noticing reconnects, and refusing it would strand
both until a reaper notices. The registry calls its victim "open-but-likely-
zombie", and *likely* is the whole of the evidence — nothing checks.

A rendezvous dial is not that case. It arrives on a schedule, and arriving
while we hold a healthy session is proof the peer did not abandon the old
connection. It cost one every time: the far side refuses its own duplicate and
closes the socket, so the newcomer that just displaced a live sender was dead
on arrival and both connections were gone. That is the mechanism behind the
session losses 0.10.5 measured and could not explain.

The two questions are now asked separately, and the answer is an exhaustive
match: a source added later must say which of the two rights it wants rather
than inherit either.

Found by an external review of 0.10.5, and confirmed here against the registry,
which states the rule it was breaking: "Don't replace a live policy-compliant
session — the first to register wins for that direction."

## v0.10.5 — 2026-09-02

**Both ends of a pair were calling each other.** For any two nodes exactly one
places the call — `we_keep_outbound = ours < theirs` — and the other waits.
`outbound_connector` has always honoured that. The rendezvous dial goes
straight to `connect_peer_active` and never did, so the node that should only
have been answering dialled too, at every pass, forever.

Its dial is refused as a duplicate, which is correct. What was not correct is
that the refusal was treated as a failure: the peer row was deleted, so the
next pass saw the address as unknown and dialled it again. The one thing that
would have taught it otherwise — a completed dial, which writes the
address-to-identity mapping — could never happen, because every dial was
refused. A closed loop, and around each refusal the working sessions were
observed closing and re-opening.

A refusal for that reason is now read as the answer it is: this address is
already ours, keep the row, stop dialling. And the direction rule reaches the
rendezvous dial as soon as the identity behind an address is known; a first
meeting still dials, because somebody has to call or the mapping is never
learned.

Measured on the production seeds, on the link that churned every 57 seconds:
reconnects went from 23 in 54 minutes to four, all inside the first 22 seconds
of start, and then none for the following 22 minutes. The node with the largest
id went from 24 refused dials to two, one per address, and then stopped.

## v0.10.4 — 2026-09-02

An external audit (report20) went through the meeting-point work. Four of its
findings were real, and this release closes them.

**A listener the operator hid was published at a meeting point.**
`build_advertised_transports` filters by `Visibility::is_advertisable()` and
says why: "Trusted and Hidden listeners stay invisible on the network — peers
learn about them only through invite-bundles." The two helpers that feed the
DHT, Nostr and LAN layers walked every listener with no such gate, so a
`hidden` or `trusted` endpoint was announced on the most public index there is,
and a `stealth` one could advertise a port that is not bound.

**`bootstrap = false` did not stop the LAN from announcing.** The flag's own
documentation is explicit — "this flag governs the ANNOUNCE and nothing else…
a node with this off still USES the permissionless layers: it asks and it
listens. Only publishing is opt-in." Layers 7 and 8 honoured that. Layer 6 put
a stable identity key, PoW nonce, port and scheme on the wire for every machine
on the segment regardless. It now listens either way and transmits only on the
opt-in.

**An address a stranger named could point into the private network.** A record
at a meeting point carries whatever its author wrote, and a DHT node answers
with whatever it likes; nothing checked that the address was globally routable
before dialling it. Loopback, RFC 1918, link-local (including the cloud
metadata address) and carrier-NAT destinations are now refused from public
sources. A private deployment reaches its peers through configured peers or the
local-network layer, which observes an address rather than being told one.

**A pass could be spent on attempts that never succeed.** The cap counted peers
met, so a failing address cost nothing against it; a rendezvous full of records
could hold a node in a dial loop for the length of a pass. Attempts are now
budgeted too, and one lookup keeps a bounded number of addresses rather than
every one it is handed.

Also: a placeholder row no longer overwrites a proven one — with slots stable
per address since 0.10.3, it would have traded a real identity for a hash and
then deleted the row on failure — and `SERVICE_COUNT` was one short of the
service list, which had left a unit test red since 0.10.0. The local gate now
prints, after its own green result, that it is the hygiene job and not the
tests.

## v0.10.3 — 2026-09-02

**A peer met at a rendezvous kept losing its row, and its session with it.**
The slot a learned peer occupied was `BASE + taken`, where `taken` counted
successful dials in the current pass and restarted every pass. Whoever was
dialled first each round took `BASE + 0` and overwrote the row of whoever held
it — the "two allocators, one concrete id" failure `synthetic_peer_id` exists
to prevent, arrived at from a single allocator using an ad-hoc literal outside
that list.

The overwritten peer's connector then found no row for its node id, which is
how a connector learns it has been retired, exited, and took a live session
down with it. From outside this looked like two seeds meeting each other again
at every rendezvous and rebuilding a link every few seconds.

A rendezvous address now keeps its slot: an address that has a row keeps it, a
new one takes the lowest free slot in a bounded window, and a full window
refuses to learn one more peer rather than evict one we are talking to.

Measured on a production seed, same node, comparable elapsed time: reconnects
to the busiest peer fell from 0.81/min to 0.19/min, `met` stopped repeating for
the same peer, and the peer table stopped emptying itself. Residual reconnects
remain and are not explained by this.

The two previous releases aimed at the same symptom (0.10.1, 0.10.2) changed
the rendezvous task's "already ours" check. That check was not the path the
re-dial came through; both fixes stand on their own merits and neither was the
cause.

## v0.10.2 — 2026-09-01

**A peer is recognised by who it is, not only by where we dialled it.** 0.10.1
stopped a node re-dialling peers it already had a session with, but only for
sessions it had opened itself: an inbound session reports our own listener as
its transport, and its remote address is the far side's ephemeral source port.
Seeds meet each other inbound, so they went on meeting each other again on
every rendezvous pass and rebuilding a session that was already working. The
check now derives the peer's id from the discovered-peer cache, which
`dial_and_learn` fills on every success, and compares that against the ids the
session layer holds.

## v0.10.1 — 2026-09-01

Two defects that 0.10.0 shipped and production found within the hour.

**A CLI convenience was killing the daemon.** `main` restored SIGPIPE to
`SIG_DFL` so that `veil-cli node dht list | head` ends in ten lines instead of a
panic. The comment beside it said this was confined to the CLI entry point, and
that a long-lived host must keep Rust's default "or an unrelated socket write
would take the whole process down". Both halves were right except the first:
`node run` enters through the same `main`. A seed was killed by SIGPIPE fifteen
minutes after starting, right after announcing itself to a Nostr relay, and
stayed down — systemd counts SIGPIPE among the clean exits, so
`Restart=on-failure` never fired and nothing logged anything at all. The
disposition is now restored only for invocations that print and exit.

**The peer table is not the record of who we are talking to.** Two seeds met
each other again on every rendezvous pass and rebuilt a session they already
had. A row learned at a meeting point lives in the autodiscovered range and is
scored out between passes, so the next pass read "not known" about a peer with
an open session, dialled it, and the far side dedupped the duplicate — taking
the working session with it. The check now also asks the session layer.

## v0.10.0 — 2026-09-01

A node can now find the network and actually join it. Until this release it
could only do the first half, and nothing said so.

**A dialler that does not know who it called was waiting to be spoken to.**
`perform_ovl1_handshake` picks which side writes its HELLO first from whether
the remote identity is known — the accepting side reads first, so a prober
that says nothing gets nothing back. That rule is worth keeping. But a peer
found at a meeting point comes with an address and no identity, so the dialler
took the accepting side and waited, while the real accepting side also waited.
Ten seconds of mutual silence, then `read OVL1 frame header: early eof`,
reported as a peer that could not be reached. One value was carrying two
unrelated facts; direction now comes from the session source, which knows it.

This is why local-network discovery worked and the DHT did not: a LAN
announcement happens to carry the peer's key, and six bytes of compact peer do
not.

**A rendezvous dial hung up on the peer it had just met.** It connected through
the debug-session path, where closing the handle is what dropping it means:
`session.open` and `session.close` eight milliseconds apart, and a node at zero
sessions having met everybody it was looking for. The row is a full peer by
then, so it goes to the ordinary reconnect loop.

Measured from a node with no peers, no bootstrap peers, no listener and no
compiled-in seeds: three peers met at the rendezvous and the sessions held.

**A third meeting point, on public Nostr relays.** The other two are UDP, so a
network that drops UDP leaves a node with no way in at all — an ordinary shape
for a hotel or an office. Relays speak WebSocket over TLS on 443.

Two things the specification does not mention, found while building it. The
event id is signed RAW: `k256`'s `Signer::sign` hashes the message first, and
signing `sha256(id)` produces signatures this code verified happily and every
relay rejected. And the author key is derived per epoch — the rendezvous label
rotates daily so nobody can watch one place and see who keeps arriving, and a
fixed author would have handed that straight back.

**A node no longer dials its own announcement.** A meeting point does not know
who is asking, so a node that announces itself reads its own record back on the
next pass. It was dialling its own listener and logging the timeout as an
unreachable peer, every fifteen minutes, for as long as it ran.

**The seed lists are empty, and now the build says so.** `production-seeds`
compiled whether the list held four entries or none, while the module doc said
the source shipped none — which is how it sat populated for months. The three
network flags settle which network a binary belongs to; none of them compiles
in an address, and a test requires both lists to stay empty.

## v0.8.5 — 2026-08-30

One fix, from the report18 audit, and it is about what an upgrade quietly
forgets.

**A bare authorization bit costs standing, not the conversation.** A build
older than the authorization stamp wrote a single bit: this peer was proven
once, and it cannot say for how long. Restoring that as `authenticated_until =
0` is right, and it is what stops a bit outliving a revocation — the test that
pins it says so and still does.

But `ever_proven()` was derived from that same field, and `ever_proven` is the
question EVICTION asks. So the migration also answered a question nobody meant
to answer: a conversation that had been vouched for came back **droppable**.
The documentation on `ever_proven` says in as many words that this must not
happen — a conversation whose evidence has merely gone stale still decrypts,
still belongs to the peer it was agreed with, and must not become a slot an
inbound prologue may take — and an upgrade is the one moment when every
conversation on the device is in that state at once. Under TTL or quota
pressure the proven session is dropped, the peer no longer attaches a
recoverable prologue, and the channel has no way back.

So the two questions get two fields. The history bit goes into
`proven_before`, restored from the byte the legacy blob already carried and
written back to that same byte: **no format change**, and an older reader sees
exactly what it always saw. Standing still comes from the stamp alone.

One test fixture had to say what it means. `plant` made an "unproven"
conversation by zeroing the stamp of a blob cut from a proven one — which under
these semantics is precisely a migrated legacy conversation, and deliberately
not droppable. It now clears the history bit too, so the five eviction tests
keep testing eviction.

## v0.8.4 — 2026-08-28

One fix, and it is why mail deposited for an offline peer never reached them.

**A sealed introduce has to fit TWO cells, and only one of them was checked.**
The sender packs an introduce into one 8192-byte anonymous cell on the way to
the rendezvous. The rendezvous then forwards that same ciphertext down the
RECEIVER's circuit, where it must fit one circuit-data cell. Nothing tied the
two numbers together — the cap's own documentation said as much — and on
2026-08-20 they crossed: circuits stopped sharing one global 16384-byte cell
and began choosing their own (2048 today, 1024 the protocol minimum), while
`MAX_INTRODUCE_CIPHERTEXT` stayed at 8058.

Everything in that gap was accepted by the sender, sealed, routed, and dropped
by the last relay, which cannot wrap it:

    anonymity.relay_chain.introduce.circuit_oversize
    introduce ct=4368 B exceeds one return cell; dropped

Measured live against all three production relays on 2026-08-28. A contact
request deposited for an offline peer was answered by the relay 58 times over
two hours and not one answer arrived, so the receiver never acked and the relay
kept re-serving it. The only answers that got through were the 2-byte EMPTY
ones from the relay that had nothing to send, which is why the mailbox looked
healthy from every angle except delivery.

The cap now takes the smaller of the two legs. A receiver's cell size is its
own choice and the sender never learns it, so the safe number is the smallest
any circuit may negotiate. Messages past the cap are not refused — they
fragment, as they did before the cell bumps.

**The android media-engine build named one ABI for all three.** Two lines in
`build_veil_media_so.sh` spelled `aarch64` by hand: the sysroot library path
and the API-26 retarget. armeabi-v7a and x86_64 searched an arm64 library
directory and failed at link with `cannot open crtbegin_so.o`, and compiled
against API 23 while `-D__ANDROID_API__` said 26. Both now read the triple
clang was actually given, and a toolchain missing an ABI says so by name.

## v0.8.3 — 2026-08-28

One fix, and it is why a contact request could not be sent on the production
network at all.

**A recursive DHT query went to peers that had opted out of serving one.**
`Contact::dht_service` says in as many words that it gates "store target, walk
hop, FIND_NODE referral" — a recursive GET is all three at once — and neither
candidate selection in the resolver consulted it. Both sorted the session peers
by XOR distance to the key and took the closest K.

The ordering made it worse rather than diluting it: an opted-out peer that
happens to sit close to the key is picked FIRST. A phone opts out by default,
so behind one NAT it is precisely the desktop's nearest session peer, and two
such peers exhaust a budget of K before a seed is ever asked.

What that looked like from the app: sealing a mailbox blob needs the
recipient's instance registry to know which devices to seal an envelope for.
The registry "did not resolve" while the record sat on all three seeds the
whole time, so nothing could be sealed, nothing was deposited, and a friend
request never arrived. Reproduced on two stand nodes against the production
seeds before the fix, and confirmed arriving after it.

Both selections now drop opted-out peers before sorting, and the filter cannot
empty the list: a node whose every session peer has opted out still asks them,
because a query that cannot be answered beats one that is never sent.

## v0.8.2 — 2026-08-28

The audit pass behind this release closed the low and medium findings of
report17 in this repository, and then went back and proved each fix is held
by a test that fails when the fix is removed.

**A refused send no longer costs a whole discovery round.** A PEX walk gave
up its entire round on the first peer that would not take the frame; it now
tries the next candidate, up to three attempts, so one unreachable neighbour
stops costing every neighbour behind it. The identity self-check spawned
alongside the republish task is owned by it as well, and dies with it instead
of outliving the runtime that started it.

**A relearned handshake nonce goes to the row it was learned from.** The
anti-replay write followed the peer's current row, so a peer that reconnected
at a new address had the nonce written against the wrong record. The row is
compared with the one that was dialled before anything is written or
persisted; a stale row skips the write without refusing the session.

**Diagnostic probes are bounded, numbered and stop when asked.** Ping and
trace took their count, interval, timeout and hop budget from the caller with
no ceiling, numbered their replies from a global counter that could collide
between concurrent operations, and kept running after the requester was gone.
Every parameter is clamped, sequence numbers come from a per-operation
allocator, and each loop stops as soon as its channel is closed. Latency
statistics are accumulated as running min/max/sum rather than a growing
vector.

**The ephemeral rendezvous signing key stops being printable.** It was a
`String` behind a derived `Debug`, so anything that formatted the
advertisement carried the private key into the log; it is now wrapped so it
is wiped on drop, and its `Debug` shows a redacted field.

**A put at the cold tier's cap cannot evict what it just wrote**, and the
overwrite of a key already on disk evicts nobody — the second half had no
test, and this release adds one that reads the bytes back through the
allocation rather than trusting the length.

**Documentation that had outgrown the code.** `mailbox_seal` announced itself
as wired into nothing while the node sealed and opened every mailbox blob
through it; the header now says so and a guard fails if the two disagree in
either direction.

## v0.8.1 — 2026-08-26

A patch release whose whole point is that the version now tells you which build
you have. Everything here was already on `main`; none of it was in a tag, so
two servers reporting `veil-cli 0.8.0` could differ on whether an exit checks
who it carries.

**An exit now knows whose traffic it carries.** A node with the exit switch on
served every peer that could reach it: there was no allowlist, so anyone who
turned it on was running an open proxy for the whole network.
`[proxy.exit]` gains `allowed_node_ids` and `allow_all`, admission is checked
BEFORE the destination header is read, and a node that is enabled but admits
nobody says so at startup (`proxy.exit.closed`) instead of failing every stream
in silence.

Read the compatibility note before upgrading a server: an exit configured
before this release names nobody, and an empty allowlist means NOBODY. Give
every exit its `allowed_node_ids` first, or set `allow_all = true` if an open
exit is what you want. Nodes that do not enable the exit are unaffected.

**A refused stream now says so.** Eight failure paths in the exit closed the
connection without answering, so the client waited out its own timeout and
reported a hang where the exit had made a decision. Each of them now writes a
status byte: denied, resolve failed, connect failed.

**A config the daemon cannot READ is not "no reflector".** An unreadable
config was treated as an empty one, so a permissions problem looked like a
deliberately empty reflector list.

**The hygiene gate can start again.** `fuzz/` is not part of the workspace, so
the v0.8.0 version bump left its lockfile pinning 0.7.0; `--locked` then killed
the FIRST step of the gate on every push, and fmt, clippy, policy and audit had
not run since the last release.

## v0.8.0 — 2026-08-25

The minor digit moves because two wire surfaces gain a field, both additively:
a mailbox FETCH may now carry a list of records the caller cannot use yet, and
the realtime datagram lane can rotate its key by negotiation. Old peers read an
empty list and never rotate; new peers reading an old one see what they saw
before. Nothing in this release is a flag day.

Most of what follows came out of a report audit, and the last of it out of
running the test suites on Windows and on aarch64 Linux for the first time.
That last step earned its keep twice over: it found a regression this very
cycle had introduced, and a defect that had been there all along.

**Durability on Windows was a comment, not a barrier.** `atomic_write` — the
helper under the identity document, the master file, the config store, the
runtime state and the updater's own installed-version file — fsynced its
content and then published it with a bare rename. `fsync_dir` is `Ok(())` on
non-Unix and std's rename passes only `MOVEFILE_REPLACE_EXISTING`, which
replaces the target without flushing it, so that platform took no barrier at
all. It renames through `MOVEFILE_WRITE_THROUGH` now. The first cut of that
change dropped std's `ACCESS_DENIED` fallback and broke a sibling project's
compaction outright; the fallback is back, and only running on Windows found
it.

**Owner-only writes never worked on Windows.** The staging file was opened for
`GENERIC_WRITE`, and `SetSecurityInfo` needs `WRITE_DAC` to put the owner-only
DACL on the handle, so every such write failed before a byte was written — and
that helper is what `sovereign_flow` saves identity secrets through. On that
platform they could not be saved at all. The mask now asks for what it uses.

**A rekeyed realtime lane could go deaf.** The receiver is told about a
rotation over a channel that held one slot, and the producer dropped a new
rotation when the slot was full, on the reasoning that the pending one
superseded it. It is the other way round: the pending one is stale and the
discarded one is what the peer had already moved to. A watch carries the
latest key now.

**PEX walks answer along the path they took.** A terminal challenge went
straight to the origin with no reverse route and the response went to the first
active peer rather than the challenger, so a multi-hop walk could neither
deliver its challenge nor answer the right node. The path is remembered per
walk, and one walk buys one proof rather than twelve.

**Accounting that a restart could reset.** A cold DHT record could buy another
lifetime by surviving a restart, and the per-origin quota did not survive one
at all. Both are now recomputed from what is on disk rather than from what a
process remembered.

**Beacons carry their provenance.** A public receive API erased `FrameOrigin`
and the documented wrapper then marked every frame `Sealed`, so a downstream
built from the recommended composition could give a plaintext LAN beacon
gateway privileges in a keyed realm.

**Admission that one peer could exhaust.** A flood of first contacts is drawn
from one pot now, the banked skipped ratchet keys have an aggregate ceiling,
and a peer's device keys are a set rather than one slot that siblings
overwrote.

Smaller: an operator can pin which DNS-discovered seeds they accept; identity
creation says up front whether that identity will ever be able to add a
device; a claimed key file with no bytes yet is no longer reported as corrupt;
two first starts on one directory settle on a single decapsulation key; and a
relayed cell is billed whichever way it travels.

## v0.7.0 — 2026-08-24

The minor digit moves because the wire breaks, and unlike v0.6.0 this one IS a
flag day. Three changes are length- or token-sensitive with no branch for the
old shape: circuit cells, the hole-punch token, and the LAN beacon port. A
v0.7.0 node and a v0.6.0 node still speak OVL1, but they cannot share a
circuit, cannot punch each other, and cannot hear each other's beacons. Network
and clients move together.

Most of what follows was found by measuring an idle phone rather than by
reading code, and the theme is the same throughout: a node was paying to talk
to itself, and paying in a shape an observer could match.

**A circuit's cells are the size that circuit negotiated, and that size is now
2048 bytes.** The cell size used to be one number for the whole network, and a
heartbeat showed what that costs: the eight-byte `CIRCUIT_HEARTBEAT_MAGIC` rode
a full 16410-byte cell every 15 seconds, measured live as 56% of an idle
phone's traffic, with RelayChain cells accounting for 73.8% of every body byte
exchanged. Bandwidth is the smaller half. The larger half is that one global
size is an invariant a classifier can write a rule against — 16410 bytes every
15.0 seconds, without decrypting anything. Uniformity has to hold where the
leak is, within one circuit against the hop that sees all of its cells; it
never had to be the same number everywhere. The setup layer now carries the
size, every hop stores it and refuses a cell of any other size, and the stream
frames to its circuit's MSS instead of a compile-time maximum. 2048 rather than
the 1024 floor: 1024 buys roughly 0.3 GB/month more while doubling the bulk
cost, turning a 5 MB transfer into ~2500 cells instead of ~310 and handing an
observer more timing samples per byte. What this does not buy is per-circuit
variety — the classifier's free invariant moves from 16410 to 2074, it does not
disappear.

**A hole punch belongs to a veil, not to whoever knows the token.** A punch was
authenticated by its attempt token alone, and the token travels over
signalling, so it crossed whatever boundary signalling crossed. Not
hypothetical: the production seed on one host held punched sessions with all
three testnet seeds and a testnet phone — 60 punches in one log window,
cross-network peers making up 52% of the production seed's frame traffic and
58% of the testnet seed's, while a debug phone whose seed assets list only
testnet spent 35% of its bytes on a network it has no business being in. A
punched QUIC path carries neither of the two things that separate the
deployments, since no listener port is involved and obfs4 is not in the path.
The token on the wire is now derived from the deployment's PSK plus the
signalled token rather than sent, so reading signalling is no longer enough to
punch. Packet layout is unchanged. Nodes with no PSK share a public tag and
keep working with each other exactly as before. This is a correctness boundary
and not a security one, and the code says so: the PSK ships inside every
release binary, so it stops accidents, not a deliberate joiner.

**The LAN beacon gets a port of its own, and finally leaves the host.** Two
nodes on one host could not both run mesh — the second bind failed and mesh was
silently disabled. `SO_REUSEPORT` on the realm socket was measured before being
taken, and the measurement forbade it: across two processes sharing one port,
broadcast reached 4/4 and 4/4, but unicast went 0/10 and 10/10. The realm
socket carries both, so sharing its port would have repaired discovery by
silently stealing half the data it exists to deliver. The beacon moved to
255.255.255.255:9101 on its own shared socket instead, the realm socket stays
exclusive, and a node no longer discovers itself — a shared beacon port means
its own broadcast comes back, and the receiver had no notion of who it was. In
the same area, the beacon had never actually left the machine: the socket was
missing `SO_BROADCAST`.

**A keepalive stops being the one frame with one size.** The OVL1 keepalive was
a bare 24-byte header on a jittered but steady cadence. Encryption hides what a
frame says, not how long it is, so that pair was matchable without decrypting
anything. It now carries 1..96 random bytes, and its ack draws independently
rather than mirroring the request, because a 60-byte question answered by a
60-byte answer is still a constant relationship. The body means nothing and is
never read, which is why a peer built before this accepts it and replies
normally — no flag day in this one.

**An idle node stops asking the network about itself.** `resolve_fresh_rendezvous_ads`
walked all eight DHT ad slots for any receiver including ourselves, though for
our own ad the local mirror is exactly what we published. The pinned-circuit
refresh fires every ~304 s forever on a node with no traffic, and each turn
drove a full eight-slot walk: 48 FIND_VALUE frames across a 1798 s capture,
about half of all recursive DHT traffic and roughly 9% of an idle phone's bill.
One walk began 22 seconds after the node wrote the very ads it then went
looking for. Alongside it: an idle node kept re-walking its own ad eight slots
at a time, a node was told how to reach itself, the ad TTL was short for a
reason that had been fixed five days earlier, republishing our own records is
now background work so frames can pack, a peer that already holds our records
is not sent them again, and route news is relayed once rather than repeatedly.
A coalescing window was measured and deliberately not taken.

**A peer's refusal to serve the DHT now outlives the things that kept erasing
it.** A refusal had to survive its contact being deleted, a session being
opened, a referral arriving from elsewhere, and a FIND_VALUE walk seeded from
sessions that erased the answer. Each of those was a separate path that read a
peer as willing again.

**A peer is written down only once a handshake proved it.** `persist_discovered_peers`
wrote every non-configured entry, and peer exchange inserts what it hears
before the first dial, so gossip reached `peers_discovered.json` with nothing
behind it and every start dialled the whole file forever. Three production
seeds came to advertise transports on a testnet port this way; deleting the
entries by hand brought them back within two hours, because the neighbours kept
handing them out. Peers are now persisted from the handshake path, and a PEX
response serves only peers we hold a live session with — expressed as a newtype
whose only constructor names the live set, so a later edit cannot quietly go
back to serving the pool. Which peers we walk is untouched; that is a separate
question from which peers we vouch for. A NAT probe also stops retrying a
target that will not answer.

### Fixed

- `cargo audit (fuzz lockfile)` had been failing on every main run since the
  cell-size work merged: two dependencies added by commits above never reached
  `fuzz/Cargo.lock`, and `--locked` refuses to update it silently. The local
  hygiene gate does not run that step, which is how a green run locally sat on
  top of a red main for a day.
- One node, one slot: a peer could occupy more than one.
- A closed pipe is no longer a crash in the CLI.
- The capture tool named onion cells after a family that no longer exists, so
  the instrument lied by name.
- A counter nothing renders is a counter nobody can read; circuit-table
  headroom is now exported, with a test that covers the accessor by the break
  it would actually take.
- A resumed handshake states nothing and must not overwrite what the peer said.
- Three quarters of every obfs4 frame's padding was the maximum, which is the
  opposite of padding.
- An address that is real somewhere is not real here.
- A home IP recorded in a June live-test note was redacted from the docs.

## v0.6.0 — 2026-08-19

The minor digit moves because the wire and the FFI both gained surface. Nothing
here is a flag day: a v0.6.0 node and a v0.5.2 node exchange frames normally.

**An identity can be more than one device.** A signed identity document names
every device key under one master; a device that holds nothing can be named
into a family and adopt the document that names it; a linked device is served
the history that predates it, in slices when one envelope no longer fits.
Revocation retires a key and leaves a tombstone that survives a merge, so an
older copy of the document cannot resurrect a device that was removed. The
merge is a union in both directions — wholesale adoption used to roll delegated
keys back.

**A peer may ask not to be a DHT service candidate.** `cap_flags` gained
`NO_DHT_SERVICE`, advertised from `[dht] participate`. The bit is NEGATIVE on
purpose: a node built before it advertises no flag and is read as willing, so a
mixed network keeps behaving as it did. A peer that declines stays in
everyone's routing table — the table is also the answer to "do I know this
node", and evicting it would make it unreachable, which is the opposite of what
it asked for. `veil_dht_no_service_skips_total` counts the candidate slots it
is passed over for, because a mechanism nobody can measure is one nobody can
tell from a mechanism that silently does nothing.

A defect found only by running it live: the bookkeeping that opens a session
inserted `Contact::new(peer, "")` through the TRUSTED path, which carries
defaults, so it erased the capabilities the handshake had just stamped a moment
earlier. `discovery_mode` had been losing the same argument since long before
this branch — a peer that asked not to appear in FIND_NODE answers reappeared
in them on every session open. Contacts now carry `caps_known`, and an insert
that states nothing keeps what is already known.

**The mailbox serves a device's own box**, drains oldest-first across both
boxes rather than starving one, gives every await inside a PUT a deadline — one
deposit that never returned used to wedge every other one — and stops
destroying a sender it could not resolve.

### Fixed

- Compaction waited on a lock it held itself; the shutdown chain was protected
  against exceptions but not against hangs.
- The hygiene gate had been failing at its first step since 2026-08-14, and
  behind it the TEST build did not compile in three crates: a handshake
  parameter and two struct fields added by the work above never reached the
  call sites in test code. An FFI entry point reached production the same way —
  it reads the node config through the OPTIONAL `veil-cfg` dependency and
  carried no feature gate, so it compiled only because every consumer happens
  to turn that feature on.
- `h2` to 0.4.16 for RUSTSEC-2026-0258. It arrives through the DNS resolver in
  `veil-bootstrap`, so it is linked into every client, not only into paths that
  speak HTTP.
- A test waited for the admin socket's PATH to appear when what it needed was a
  connection to be accepted; `bind(2)` creates the path and `listen(2)` is what
  makes a connect succeed.

## v0.5.2 — 2026-08-13

**A checkout without the prebuilt call engine now builds.** `veil_media`'s
Linux and Windows CMake raised `FATAL_ERROR` when `libveil_media` was absent,
and that library is gitignored — so `flutter build linux` on a clean clone of a
host project could not start. iOS was the same shape through the podspec's
`-force_load`. That is the opposite of how this project treats its other
optional natives, whose stated contract is that the bundle builds, runs, and
reports the feature as unavailable.

The strictness is not gone, because it was earning its keep: a host app once
shipped with no engine and every call, voice message, video note and
transcription threw at first use. It is now conditional, and the default is the
safe one. In order: `-DVEIL_MEDIA_REQUIRE_ENGINE`, then the environment
variable of the same name, then `CI` being set — which every runner does and no
developer shell does — and only then the permissive path. Forgetting to say
anything on a runner lands on strict; reaching permissive from a release takes
writing `=0` deliberately. The environment variable exists because
`flutter build linux|windows` drives cmake itself and forwards no cmake
arguments, so `-D` is not reachable from that path at all.

Verified on an aarch64 Linux host with the engine moved aside: the build
completes, warns, and produces a bundle with no engine in it; the same host
with the original CMakeLists fails, which is the reported symptom. And with the
engine restored: builds, no warning, engine present.

`veil_flutter`'s own `FATAL_ERROR` deliberately stays strict. That library is
built from this repository by `scripts/build-native.sh`, so its absence means a
skipped build step rather than a dependency nobody can obtain.

## v0.5.1 — 2026-08-13

**Windows stops shipping a library that exports nothing.** `veilclient-ffi`
carried `#![cfg(unix)]` at its crate root, so every entry point compiled away
off Unix. `cargo build` still exited 0 and produced a DLL, and that DLL
shipped: the published xVeil v0.9.1 Windows bundle contains a 105 KB
`veilclient_ffi.dll` whose export address table has **zero** entries, beside a
`hidden_volume_ffi.dll` with 285 in the same archive. The app on Windows had
no way to reach the network at all — no embedded node, and no `veil-cli` in
the bundle to fall back to.

The gate turned out to be over-broad rather than load-bearing. Its own comment
said it existed to keep a Windows type-check green "without breaking any actual
downstream consumer", and that assumption had simply stopped being true. The
pieces underneath were already written: the named-pipe listener in
`veil-local-transport`, the `#[cfg(windows)]` connect path in the IPC client,
and the `not(unix)` endpoint default in `veil-cfg`.

Measured rather than inferred, because a green build is what certified the
empty DLL in the first place: **131 exported `veil_*` entry points**, including
`veil_abi_contract_hash`, which the Dart side reads before any other symbol;
and an embedded node that boots on a real `C:\Users\…\Temp\…` runtime
directory, binds its admin endpoint and stops cleanly. The Windows gate now
asks that question on every run — it reads the export table `GetProcAddress`
consults, with a floor rather than a non-empty test, and it fails loudly when
it cannot run at all rather than reporting an absence it never measured.

Also here: three fixes to that gate itself, which had been red since a
toolchain pin landed. Cross targets were being installed onto the toolchain the
setup action brings rather than the one `rust-toolchain.toml` pins, so the
aarch64 leg had been failing for a week with `can't find crate for 'core'`; a
named-pipe test panicked in its own setup outside a tokio runtime and had never
passed since it was written; and the embedded-node job blamed a test filter for
what was really an absent crate.

No wire, ABI or on-disk change. A v0.5.0 node and a v0.5.1 node are
interoperable, and the v0.5.0 flag day below still describes the boundary that
matters.

## v0.5.0 — 2026-08-12

**Flag day. A node built from this release cannot exchange a frame with one
built from v0.4.2, in either direction, on any transport.** Two unnegotiated
wire changes force it and neither has a compatibility window. The OVL1 frame
header's version byte goes 1 → 2, because the AEAD now authenticates the whole
24-byte header instead of three bytes of it; the two associated-data
constructions are not interoperable, and the version byte exists so that the
refusal is legible — a peer from the other side is rejected at `decode_header`
with `UnsupportedVersion` rather than failing every AEAD open with an error
indistinguishable from corruption or an attack. Separately, the anonymous cell
grows 512 → 8192 bytes, which every relay and client on a network must agree on
by construction. **Roll clients, relays and seeds together.** A partial rollout
does not degrade gracefully; it partitions the network along the version line.
Within the roll, take relays before clients: `CircuitBuilt` ACKs grew 4 → 36
bytes with no negotiation of their own.

Two consequences of that boundary are worth stating plainly, because neither
looks like a version problem in a log. An old peer dialling an upgraded node is
refused before it can say who it is, and `UnsupportedVersion` is one of the
strings the scanner shield reads as pre-protocol garbage — so a v1 seed
retrying against a v2 node is classified as a port scanner and its address is
banned for 300 seconds after five attempts in a minute. And a cell-size
mismatch is recorded as a peer violation in both directions, so the two islands
actively accumulate ban strikes against each other rather than sitting idle.
Leaving a seed behind is worse than leaving it off. ⚠️ The `WIRE_PROTOCOL.md`
docs still describe version 1 and were not updated in this range.

**Every host that links `veilclient-ffi` must be rebuilt against this release.**
The C ABI broke in five places that kept their old symbol names, most sharply
`VeilRecvCb`, which gained a `provenance` byte in the MIDDLE of its argument
list — an old host's callback would read `reply_id` out of a register holding
one byte, which is memory corruption rather than a link error. The library
therefore now carries `veil_abi_contract_hash`, a SHA-256 over the generated C
header, and a caller holding a different one is refused at load rather than
called: the Dart side throws `VeilAbiContractMismatch` and no library handle
escapes. There is no shim and no fallback, by design — a mismatch is a rebuild,
not a downgrade path.

**What does not break.** No config key was removed or renamed, so a v0.4.2
`config.toml` still parses under the strict parser and every added key carries
a default. No state path moved. The mailbox database opens in place with
its record layout byte-identical, the ban file is unchanged, and the
update-manifest encoding has an empty diff — a v0.4.2 updater consumes this
release exactly as it consumed the last one. `ogate` and `oproxy` have no
commits in this range at all, so their flags and environment overrides are
untouched. Nothing under `ansible/`, `docker/` or `monitoring/` needs mirroring.

**What an operator with a running node has to do.** Stop it, replace the
binary, start it — plus the following, each of which applies only if it names
something you actually set. If `require_signed_config` is on, pin an issuer
before upgrading: enforcement without `VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY` now
refuses to boot where it used to proceed, and self-certification no longer
counts. `chmod 600` the file named by `key_passphrase_file`; a group-readable
one is now refused rather than warned about. If you have a sovereign identity
and no `mlkem.key` file, decide whether you want the published mailbox key to
change — `mlkem_rotation_secs = 0` reproduces the v0.4.2 key exactly. If you
relied on DHT values surviving a restart without setting
`dht.values_persist_path`, set it: the implied path is gone, and the snapshot
format is v2 besides, so the old file is ignored once either way. Fix any script
calling `veil-cli config sign`, which now requires `--signer-key`, and drop
`--features tls-webpki-roots` from any build pipeline. Relay operators should
re-check mailbox quota sizing: quotas are charged in billable bytes now
(payload + 256 per record), so an unchanged number admits far fewer records.

### Breaking

- **The OVL1 frame header is authenticated whole, and `VERSION` goes 1 → 2**
  (external audit report4, V-01). The AEAD associated data was
  `[family, msg_type_hi, msg_type_lo]`; everything else in the 24-byte header —
  `flags`, `header_len`, `body_len`, `stream_id`, `request_id` — sat outside the
  Poly1305 tag. `tcp://`, `ws://` and `socks://` are registered transports and
  carry no outer authentication of their own, so on those an on-path attacker
  could take an AUTHENTIC frame and rewrite the parts that say where it goes:
  move a valid `AppData`/`AppClose` onto a different stream, change `request_id`
  so a DHT response is handed to the wrong waiter, or change `body_len` so the
  peer waits for bytes that never arrive, allocates for them, or tears the
  session down. The ciphertext was genuine in every case; only its placement was
  forged, and placement is where the meaning lives.

  The AAD is now the entire final wire header. It costs nothing to send — the
  AAD is never transmitted, it is the header the receiver already holds — and
  nothing to compute, because both sides already encode and decode those bytes.
  On the send path it must be built AFTER `body_len` becomes the ciphertext
  length; on the receive path it must be the header AS RECEIVED, never a
  rebuild, because a reconstructed header has `flags = 0` while a real control
  frame carries priority bits there. Both rules are in the codec doc-comment,
  and the test suite caught both while they were being got wrong.

  `HelloPayload.ovl1_major` has been on the wire since the first handshake and
  nothing ever read it. It is checked now, which turns the negotiation the
  payload always claimed to carry into one that happens, and puts a sentence an
  operator can act on into the handshake error. ⛔ The old
  `veil_crypto::session_cipher::frame_aad` is DELETED rather than deprecated: a
  caller still building the short AAD would compile and then fail every open at
  runtime,
  which is a far worse way to find out. The replacement lives in
  `veil_proto::codec`, where the header type is. The golden frame-header vector
  exists to make a wire-breaking change impossible to make by accident; it is
  updated, and the v1 vector is kept as a rejection case.

- **The published ML-KEM certificate goes V1 → V2, and version 1 is refused
  rather than tolerated.** A device published a key anyone could encapsulate to
  and nothing that could authenticate it. The certificate now carries a
  `ratchet_x25519_pubkey`, its signature context moves from
  `veil.mlkem_cert.v1` to `veil.mlkem_cert.v2` — the only domain-separation
  string that changes in this release — and the size cap goes 2048 → 2560. This
  is a DHT-published record, so it is a second versioned wire break independent
  of the frame header, and it is a hard refusal on the old version by design.

- **The route-request signature no longer covers `ttl`, and this one carries no
  marker at all.** The signature covered a field every hop rewrites, and nobody
  checked it — a hop could edit the TTL of a signed request and the signature
  still verified for the fields it did cover, which is the worst of both. The
  signed bytes are now `target || requester || req_id`, and TTL is bounded on
  ingress instead (`MAX_ROUTE_REQUEST_TTL = 8`). ⚠️ The 133-byte wire layout is
  unchanged and `ttl` still sits at the same offset, so an old and a new node
  exchange byte-identical packets whose signatures simply never verify against
  each other. There is no version byte and no error that names the cause. It is
  gated in practice only by the frame-header version above; do not rely on
  anything else catching it.

- **The second route-gossip plane is removed rather than have its defences
  rebuilt.** `RoutingMsg::RouteUpdate` (0x12) and `VersionVectorSync` (0x13) and
  the 138-byte `RouteUpdatePayload` are gone, and the message codes are
  tombstoned so they cannot be reused. An old node's 0x12/0x13 frames now decode
  to `UnknownMsgType`. DHT-routed forwarding was already carrying this traffic;
  the second plane existed to be hardened rather than to be needed.

- **The anonymous cell grows 512 → 8192 bytes.** The introduce path had two
  cells and only one of them ever grew. Sender → rendezvous rode a 512-byte
  anonymous cell; rendezvous → receiver rides a 16384-byte circuit-data cell,
  bumped 384 → 4096 → 16384 on 2026-07-02 for onion-stream throughput. Nothing
  tied them together, so the small one stayed the binding limit: 267 payload
  bytes at three hops, 135 after the introduce seal and fragment header.
  Anything longer fragmented, every fragment arrived in a whole 16 KiB cell, and
  three-or-more-fragment messages were sent three times over for bulk/reply
  redundancy. A ~6 KB mailbox FETCH reply was 46 fragments and up to 138 cells —
  2.2 MB of wire for 6 KB of mail. Measured on two live devices: 41 MB to
  deliver ten 7-byte chat messages.

  At 8192 the three-hop fragment budget is 7815 B, so a full 6144-byte
  `AuthDeliver` — the largest thing this path carries — is one fragment. The
  bulk redundancy never triggers, the all-or-nothing reassembly has nothing to
  lose, and the 16 KiB inbound cell stops being 99% padding. 8192 rather than
  matching the circuit cell at 16384 because the payload ceiling is what sets
  the useful size, and doubling past it would only double what a small send pads
  to on the way out. `MAX_INTRODUCE_CIPHERTEXT` stops being a hand-sized 320 and
  derives from the cell instead — the same defect in miniature, a number sized
  by hand against a cell and left behind when the cell moved.

- **The mailbox deposit chunk is sized for the cell it actually rides**:
  `MAILBOX_PUT_CHUNK_DATA_BYTES` 240 → 7680, `MAX_MAILBOX_PUT_CHUNKS` 256 → 8.
  A number hand-derived against the anonymous cell, in a crate that cannot see
  that cell, kept in step by a comment — and the comment was right when it was
  written. After the cell bump it was actively harmful: a chunk is ONE cell on
  the wire whatever it holds, so a ~1.5 KB deposit was seven chunks, seven whole
  8 KiB cells for 1.7 KB of content, worse than before the bump rather than
  better. What bounds relay memory is the product of the two numbers, not either
  factor, so the reassembly ceiling stays at the ~60 KB it was instead of
  quietly becoming 1.9 MB per in-flight deposit. Mirrored in xVeil as
  `kMailboxPutChunkDataBytes`.

- **`CircuitBuilt` ACKs now carry a terminus proof and grew from 4 to 36 bytes**
  (audit VL-01). The ACK's only field was a circuit id, and every hop knows the
  id of the link it sits on — including the first hop, which knows the very id
  the originator matches on. Any hop could therefore synthesise the ACK and
  have the originator mark a circuit CONFIRMED and freeze that path, without a
  byte having reached the terminus: a black hole that looks healthy.

  The originator already generates a fresh `circuit_key` per hop and delivers
  each one sealed to that hop's X25519 key inside the setup envelope, so the
  terminus key is known to exactly two parties and to nobody in between. The
  ACK now carries `blake3::derive_key(<context>, terminus_circuit_key)`, which
  proves both "this came from the terminus" and "this is that circuit" — the
  key is fresh per circuit — and the originator confirms only on a match,
  compared in constant time so a forwarding hop gets no prefix oracle.
  Intermediate hops re-tag the circuit id and pass the token through untouched.

  There is no version negotiation on relay-chain messages and the decode is
  exact-length, so **this is an unnegotiated wire break**: a node of the old
  shape drops these frames and confirms nothing. That is the pre-existing safe
  state — an unconfirmed circuit is re-selected by path maintenance rather than
  frozen — but it does mean circuits do not confirm across a version boundary.
  **Roll relays before clients.**

- **A rendezvous cookie is now derived from the registration key, so claiming
  one takes a preimage rather than merely being early** (audit VL-02).
  First-registration-wins only defends the cookie while the legitimate service
  holds the entry. It does not survive the service losing it — the rendezvous
  restarts, or the 600-second TTL reaps a subscription during an outage — and
  the cookie is public, because it rides in the DHT ad so senders can find the
  service. Whoever registered first after that moment owned it, and the real
  service was then rejected as the squatter on its own name. The relay cannot
  tell the two apart: it never learns the receiver's `node_id` (that is the
  property the design exists for) and it never sees the ad, so everything it
  knows is in the registration payload. The relay now recomputes the cookie
  from `reg_pk` and refuses any other pairing, which also lands against an
  EMPTY registry — precisely the window first-wins never covered. It costs
  nothing in key lifetime: a sovereign service already derived both its cookie
  and its `reg_pk` from `(identity_seed, period, slot)`, so they already
  rotated together. `register_onion_circuit` no longer TAKES a cookie; it
  returns the one it registered under, which makes the mispairing
  unrepresentable rather than merely wrong. **Breaking for anyone driving
  `register_onion_circuit` directly, and any cookie minted by an older node is
  unregisterable at an updated relay.**

- **The live path could not register the cookie it addressed, and the fix
  changes what a receiver publishes.** Every onion-stream circuit registration
  had been refused at every relay since the cookie was bound to the
  registration key: the stream path minted its cookie from the `node_id`
  instead, a value no key can claim. So the registration was refused, no
  `CircuitBuilt` ACK came back, and no cookie ever reached the splice table —
  in both directions, on every relay, for every peer. Field evidence across two
  devices and three production seeds: 2733 inbound circuit confirmations timed
  out, 4453 outbound opens failed, and not one route was ever found. Everything
  that arrived arrived through the mailbox, which is where the eight-second
  chat latency came from; a call invite, which has no mailbox to fall back to,
  went out eight times and arrived none. `open_stream_circuit` no longer takes
  a cookie either — it derives one from the key it is about to sign with — and
  the sender reads the cookie off the ad the receiver publishes once its
  receive circuit confirms. The old fallback to mailbox ads is gone with it:
  addressing a cell to a mailbox cookie cannot splice, because the relay holds
  that one in the session-keyed registry rather than the circuit one, so the
  fallback only spent circuits and ten-second timeouts on routes that could not
  carry a byte. **A receiver on this build publishes a different stream cookie,
  so its live path only meets senders on this build.** Mismatched pairs degrade
  to the mailbox, which is exactly where they already were.

- **The FFI surface carries an ABI contract hash, and five entry points changed
  shape without changing name.** The hand-written Dart bindings had no link to
  the native side at all, and the one number they restated had already drifted
  by 256 bytes. `veil_abi_contract_hash` is now a SHA-256 over the generated C
  header, derived by the same script that generates the header and the Dart
  constants, and gated in CI by regenerating all three and diffing. A caller
  carrying a different hash was built against a different ABI — same symbol
  names, possibly different signatures — so it is refused at load.

  The changes that make it necessary: `VeilRecvCb` gained a `provenance` byte
  between `src_app_id` and `reply_id`, i.e. in the middle of the argument list;
  `veil_stream_accept` gained an `out_provenance` out-parameter;
  `veil_media_open_channel`, `veil_media_open_direct_channel` and
  `veil_media_open_relay_channel` each gained `tx_key` and `rx_key`, because
  call media is now sealed on every transport rather than on one out of three;
  and `veil_media_channel_set_e2e_keys` is REMOVED, keys being mandatory at
  open. On the Dart side `configureRelayMediaCipher` is gone, `acceptStream`
  returns a third field, and the media-open calls take required key arguments.
  Additive alongside them: `veil_node_stop_timeout` and nine
  `veil_ratchet_*` entry points, so ratchet state — the one thing that cannot
  be rebuilt — has a way out of the process.

- **Two IPC payloads grew a provenance byte, and `IPC_PROTOCOL_VERSION` did not
  move.** `StreamOpenInboundPayload` goes 76 → 77 bytes and `AppDeliverPayload`
  gains a trailing byte, both carrying the sender-trust level the node had been
  computing and then dropping one frame short of the app. The node↔app IPC
  boundary is therefore byte-incompatible with a v0.4.2 build while still
  announcing version 1 on both sides. ⚠️ `ipc_wire_format_snapshot` pins nine
  payloads and neither of these two is among them, which is why the growth did
  not trip the gate that exists for exactly this — the gate's own doc-comment
  records the last time a version check passed `1 == 1` while the bytes had
  diverged. **The daemon and the app it talks to must be built from the same
  tree**; this is not a network boundary, so it is not covered by the frame
  header version. Widening that snapshot is left for its own change rather than
  folded into a release.

- **Onion call media is reframed: `MEDIA_BATCH_MAGIC` no longer exists as a
  top-level cell.** Call media was end-to-end sealed on one transport out of
  three and open on the other two; the magic byte moved inside the AEAD, so
  onion ingress accepts only `[MEDIA_MAGIC][sealed]` and the dispatch decision
  is made on decrypted plaintext rather than on bytes an attacker supplies.

- **`veil-cli config sign` requires `--signer-key`, and enforcement requires a
  pinned issuer.** A signed config authenticated whoever held the file: with
  `require_signed_config` on and no `VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY`
  pinned, the node booted anyway, and a config signed with its own
  `[identity].private_key` satisfied the check. Both are refused now, for
  `node run` and for `admin apply-config` alike, and an empty environment value
  reads as unset rather than as a pin. `veil-cli config sign` therefore grew a
  required `--signer-key <PATH>` (mode 0600 or it aborts), a new
  `veil-cli config signer-key <PATH>` mints the offline keypair, and
  `save_config` refuses to rewrite a signed config under enforcement instead of
  silently stripping the signature header. Enforcement is opt-in and defaults
  to off, so a node that never turned it on is unaffected. ⚠️ The signing
  procedure in `docs/{en,ru}/OPERATIONS.md` still describes the old flow and
  was not updated here.

- **The DHT values snapshot is versioned, and a v0.4.2 file is ignored rather
  than guessed at.** A restart handed every restored value a clean sheet and a
  fresh hour, because the bare unversioned JSON array carried neither the
  origin of a value nor its age. The file is now `{ version: 2, entries }` with
  mandatory `origin` and `age_secs` per entry, and anything that is not
  version 2 is dropped. An operator with `dht.values_persist_path` configured
  loses their cached values once, on the first boot — one republish interval of
  a cache. Separately, both the periodic writer and the restore-on-start stop
  inventing `<config_dir>/dht_values.json` when no path is configured; DHT
  values were being written next to the config on nodes that never asked for
  it. A node that relied on that implied path must now set the key.

- **A broken identity document refuses to start instead of silently
  downgrading the node.** It used to warn and continue as an unrelated,
  legacy `node_id`-keyed node — the same install, a different identity, and
  nothing in the log an operator would read as that. A MISSING document is
  unchanged and still boots identity-less; only an unreadable one is fatal.
  `[global] allow_identity_fallback = true` restores the old behaviour, and it
  has to be edited into the file, because a programmatic save patches and will
  not add a key that is absent.

- **The `tls-webpki-roots` cargo feature is removed.** It had been a no-op —
  `tls_client.use_system_roots` works in every build — so a pipeline passing
  `--features tls-webpki-roots` now fails on an unknown feature rather than
  quietly getting what it already had.

### Security

An audit pass over the transport, session, routing, mailbox and identity layers
ran through this release. The wire items above are the sharpest of them; these
are the rest, each with a regression test verified against the broken code.

- **A solved discovery proof was a bearer token, so echoing one back cost its
  owner the work they had done.** The receiver now remembers spent stamps
  rather than treating a valid proof as reusable by whoever repeats it. Route
  lookups can also no longer be suppressed by squatting the first few request
  ids: request ids come from the system RNG, as the wire documentation always
  said they did, and the via-collapsing dedup layer no longer applies to
  requests. (The route-request signature change is under Breaking — it is
  wire-visible and carries no version signal.)
- **A message could name any sender, and the check ran on the wrong path.** The
  node also decided the sender's trust level and then dropped it one frame
  short of the app, so provenance never reached the surface that displays it —
  which is why the FFI callback grew a `provenance` byte.
- **One-to-one messaging had no key agreement, so nothing was forward-secret.**
  A ratchet now exists, with somewhere to keep a conversation; a stranger who
  opened the conversation first is no longer who our messages get sealed to; a
  conversation that stops opening the peer's frames is given up rather than
  retried forever; and anyone who could reach the node could previously make it
  hold ratchet state forever.
- **The mailbox ML-KEM key was permanent, so a leak of it was permanent too.**
  It rotates now. A node's receive keys no longer outlive the identity they
  belong to, a mined nonce no longer outlives the identity it was mined for,
  and the host ticket key rotates rather than one key opening every ticket.
- **Quota and capacity defects across the mailbox.** A byte quota charged the
  payload and not the record; the per-chunk cap was documentation rather than a
  check; a fetch batch was bounded by record count, so one batch could be the
  receiver's whole quota; every anonymous depositor on the network shared one
  bucket; a squatter could hold every deposit slot; and the leaf byte quota was
  built end to end and never attached.
- **A token could name a relay it was not bound to**, and a passphrase file was
  read whatever its mode. The Falcon and ML-KEM key material no longer passes
  through ordinary heap buffers that are freed rather than wiped, a handoff
  entry no longer prints or keeps its session key, and turning on a key
  passphrase can no longer leave the key in plaintext without saying so.
- **The IPC connection cap was spent before anyone was authenticated**, and the
  admin surface now holds slots for the command that fixes a wedged node. On
  Android the call notification's actions were a request anyone could make, and
  a one-shot capability could be consumed twice.
- **The installer skipped a pinned release key on macOS.** Both `install.sh`
  and `install.ps1` now fail closed on an unverifiable download, with
  `--skip-signature` / `-SkipSignature` as the explicit opt-out. A TCP read
  treated as a frame and two fail-open update gates are closed with it.

### Added

- **End-to-end sealing for messages to an online peer**, which previously left
  the node with none at all, and a device key that can be authenticated rather
  than merely encapsulated to.
- **Ratchet state export and import across the FFI**, plus a dirty-list so a
  host with a small buffer can page through the list rather than never reaching
  its end.
- **A bounded node stop that says which way it went**, and an apply-config that
  fails fast on a dead node instead of waiting 90 seconds and then blaming a
  missing file.
- **Per-message-type and per-frame-family byte metrics**, so relay-chain and
  inbound traffic can be attributed rather than totalled.
- **A fourth production seed**, so three hosts are not the whole network.
- **A Windows build of the call media engine that actually compiles.** The port
  shipped source-only and uncompiled in v0.4.2; the screen capturer, the
  response-file driven compile, the MSVC C++ runtime link and the voice-message
  path are fixed here.

### Changed

- **The node runtime is sized for a phone when it is running on one.** The
  anonymous reply path stops sending a one-fragment reply three times, the
  mailbox ACK stops building a reply circuit no one answers, and the ratchet's
  key agreement no longer runs under the lock every conversation shares.
- **Opening a session no longer clones the whole DHT store into RAM**, and the
  cold tier is no longer read off disk once a second to hand back its keys.
- **The lazy miner's PoW nonces move out of `config.toml`** into a disposable
  `<stem>.runtime-state.toml` beside it, applied as an overlay after signature
  verification so persisting a nonce cannot invalidate a signed config. The
  config directory must be writable; deleting the sidecar costs one re-mine.
- **Mailbox quotas are charged in billable bytes** (payload plus 256 per
  record) rather than payload alone, so the configured numbers now mean
  physical bytes. Existing values admit correspondingly fewer records.
- **The toolchain is pinned in `rust-toolchain.toml`**, because an unpinned one
  silently rewrote the tree: a rustfmt release, not a commit, turned
  `cargo fmt --all --check` red across 34 files on 2026-08-05.

### Fixed

- **A deferred-init boot no longer dials the builtin seeds before its host has
  said anything.** `--defer-init` / `veil_node_start_deferred` boot from
  `build_stub_config_with_ephemeral_identity`, and the host's real config
  arrives afterwards as `admin apply-config`. That stub was `Config::default()`,
  which is `builtin_seed_policy = "auto"` — and `auto`'s condition, "neither
  `peers` nor `[[bootstrap_peers]]` is set", is what the stub is by
  construction. So every deferred boot on every host logged
  `bootstrap.builtin dialing N entry point(s): 0 configured + N builtin
  seed(s)` and opened outbound connectors to the compiled-in seed hosts,
  seconds before the config that had something to say about it was applied.

  For an embedded host that offers its user a choice about those seeds, this
  silently defeated it: the refusal is expressed as `builtin_seed_policy =
  "never"` in the config the host COMPOSES, which is the second config the node
  reads. A user who declined still reached the operator's seed hosts once per
  start, and no test on the host's side could see it — every one of them
  inspects the composed config.

  The stub now sets `builtin_seed_policy = "never"`. Nothing is lost for a host
  that wants the seeds: apply-config is a full reload, so `spawn_all_services`
  re-runs the bootstrap task against the real config and splices them in there,
  over connectors that outlive the boot. The boot dial was never the one that
  bootstrapped the node — it also carried no `[transport]`, so on any
  deployment pinning an obfs4 PSK every one of those dials failed the handshake,
  and it presented a compiled-in constant identity shared by every install. A
  deferred node given no config now stays offline, which is what deferred-init
  means.

- **Inbound frame bodies now share a node-wide memory budget.** The 16 MiB
  per-frame cap and the 30-second slow-loris deadline are both *per frame, per
  session*; nothing summed them. Every authenticated session is an independent
  reader that announces a length, allocates a buffer that big, and waits for
  the bytes — so a node holding a thousand sessions, ordinary for a relay,
  admitted a thousand simultaneous reservations of up to 16 MiB each. The
  peers need not be malicious; a synchronised burst of large legitimate
  transfers has the same shape. What makes it cheap to provoke is that the
  body need never arrive: the header alone reserves the memory. A session now
  reserves against `rx_body_budget` (64 MiB default, `VEIL_RX_BODY_BUDGET`)
  before allocating and holds the reservation until the body is consumed, so
  in-flight body memory is bounded regardless of session count. Demand above
  the budget queues rather than allocating, and cannot deadlock because every
  holder is itself bounded by the body deadline. A configured budget below one
  whole frame is raised to it — otherwise a `MAX_FRAME_BODY` frame would wait
  forever on permits that cannot exist. Giving up on the wait sheds the
  session but deliberately does **not** record a violation: saturation is this
  node's condition, and banning peers for our own congestion would turn memory
  pressure into a mesh-wide disconnect storm.

- **The reply-circuit confirmation wait no longer freezes a current-thread
  runtime.** On a multi-thread runtime the wait runs under `block_in_place`,
  which hands the worker's queue to other threads so the `CircuitBuilt` ACK is
  processed during it. On a current-thread runtime the same wait slept on the
  only worker — parking the executor and with it the inbound dispatch that
  would deliver the very ACK being waited for. It could not succeed by
  construction, and cost a full second of frozen networking to fail. That
  flavour now returns immediately: nothing is lost, since the confirmation
  could not have arrived, and the executor stays live so the ACK lands as soon
  as it can. Off a runtime entirely (the FFI admin client) the sleep is
  harmless and unchanged. The unregistered-cookie race remains open on
  current-thread exactly as it already was — closing it there requires the
  wait to be awaited rather than blocked, i.e. an async caller path, which is
  not done here.

- **A late-exiting session runner tore down the state of the session that
  replaced it.** A session owns two kinds of state. Its registrations are
  keyed by `session_id`, so removing them is unambiguous. Everything else it
  installs is keyed by *peer*: the peer's ML-KEM key and per-session DK, its
  observed address and UDP reflectors, its relay tunnels, its rendezvous
  subscriptions, and the routes that run through it — one set per peer, no
  matter how many sessions have come and gone. The teardown removed the second
  kind unconditionally.

  That is fine until a peer reconnects. A NAT'd client re-dialing evicts the
  stale session's tx entry, installs its own, and repopulates the peer-wide
  state through `on_session_opened`. The *old* runner then notices its channel
  closed and exits — and deleted the live session's ML-KEM key, dropped its
  rendezvous subscriptions and reflectors, and broadcast
  `ROUTE_WITHDRAW`/`RouteUpdate(REMOVE)` to the whole mesh for a peer that was
  at that moment connected. The peer stayed reachable while looking
  unreachable, until something re-announced it.

  All three runner-exit paths (inbound, punched-outbound, outbound connector)
  now go through one `session_guard::release_session`, which runs the
  peer-wide half only after a compare-and-remove of the current owner. The
  predicate is "does anyone still hold this peer after we removed ourselves",
  not "did we remove anything" — the latter also reports true after
  `prune_closed` or `force_reconnect_all_peers` cleared the entry with no
  successor, which would strand exactly the state this is meant to reclaim.
  Two of those paths also notified the dispatcher *before* unregistering the
  tx channel, the ordering the inbound path fixed long ago; they now match.

- **The session-close generation bumps on every runner exit, as documented.**
  It is the signal a long-lived circuit handle samples at open time to notice
  its first-hop relay churned. Only the inbound path bumped it, so a circuit
  whose first hop was an outbound session never learned that session had
  ended and kept enqueueing onto a dead route. It now bumps on all three
  paths — and deliberately outside the owner check above: a replacement is
  precisely the churn the handle is asking about, since the old session's keys
  are gone even though the peer is reachable again through the new one.

- **A rejected peer no longer writes to, or evicts from, the per-peer caches.**
  Completing a handshake proves key ownership; it does not mean the session
  will be kept. The expected-peer check, the listener allowlist, the ban list,
  the concurrency cap, directional dedup and the over-cap re-check all run
  afterwards. The seven per-peer caches were written at handshake completion,
  before any of them — so a peer that every gate rejected still got its
  pubkey, roles, cap-flags, ML-KEM key, battery, Vivaldi coordinate, alt-URI
  and membership cert into node-wide state, and, because each cache is capped,
  evicted an entry belonging to a peer we did accept. An authenticated Sybil
  cannot forge another node's `node_id`, but it can handshake in a loop and
  churn the caches of the nodes we actually talk to. `cache_peer_handshake_state`
  is now split into a `prepare_peer_handshake_state` that mutates nothing and a
  `PendingPeerState::commit` that takes `self` by value — so a reject path
  cannot have committed, because committing consumes the value it drops — with
  the single call sitting past the last gate, beside the session-registry
  insert it already guarded.

### Release notes for whoever cuts this

Auto-update: **`min_compatible_version = 0.4.0`**. This is the first minor bump
since the workflow's fallback was written, and that fallback is the `.0` of the
release's own minor line — which for `v0.5.0` is `0.5.0`, a manifest no
installed node can satisfy. **Cut this release through a `workflow_dispatch`
with `min_compatible_version` set explicitly** rather than letting a bare tag
push take the default, or every 0.4.x install refuses the update it is being
offered. The gate compares against the binary crate's own `CARGO_PKG_VERSION`,
so `veil-cli` at 0.5.0 is what a node reports about itself.

⚠️ The shell installer now refuses a download it cannot verify, and a missing
`sha256-<triple>.txt.sig` is a hard error that `--skip-signature` does not
cover — while `release.yml` still treats `RELEASE_INSTALLER_ED25519_SK` as
optional and emits no `.sig` when it is unset. At v0.4.2 an unset secret was a
silent downgrade to sha256-only; here it makes `install.sh` unusable. Confirm
the secret is set before tagging.

`veilcore` and `veilclient` rejoin the shared version line at 0.5.0. They were
left behind at v0.4.2 — that release commit bumped the 51 crates under
`crates/`, and these two sit at the repository root, outside that glob — so
their stated version has understated the tree for a release.
`veil-onion-stream` remains on its independent 0.1.x line and
`veil-vpn-helper` on its 0.1.x line.

## v0.4.2 — 2026-07-29

No Rust code changed: `cargo` builds nothing new here. The work is in the
`veil_media` Flutter plugin, which each platform builds with its own script.

### Added

- **A Windows port of the call media engine** (`veil_media/windows/`), the one
  platform it never had — android, ios, linux and macos were all present, so a
  Windows build started, looked healthy and threw at the first voice message.
  Audio needed no new code: `create_audio_device` already falls through to
  WebRTC's Core Audio ADM, so voice messages and audio calls were one build
  away. What was missing is a camera (`veil_mf_camera.cc`, Media Foundation),
  a screen capturer (`veil_gdi_screen.cc`, deliberately GDI rather than DXGI —
  correctness first), a way to reach the two veilclient datagram symbols
  without linking a Rust artifact (`veil_win_datagram_thunk.cc`, GetProcAddress
  rather than an import), and the plugin plus build script to produce the DLL.

  ⚠️ **None of it has ever been compiled.** It was written on a host that
  cannot build it, and the first compile will be the `webrtc-windows` workflow.
  Expect to fix it before a DLL comes out; the file headers say so too. It
  ships in this tag because it is source-only and outside the cargo workspace —
  nothing in a veil build touches it — so a release carries it without carrying
  any risk to the binaries.

### Documentation

### Documentation

- **The deferred obfuscated-UDP transport is written down** (`TASKS.md`). It
  was parked by operator decision on 2026-07-05 and then disappeared: the
  design note lived in a session scratchpad, no backlog row was ever added, and
  the only trace left is the `veil-udp-obfs` crate — which looks like a
  finished feature because it is used, just for something far smaller than what
  was intended. The row states what the crate is (a per-datagram AEAD wrapper
  for mesh realm DATA), what it is not (no handshake, listener, stream or
  reliability layer), what completing it would cost, why it was parked (the
  failure that prompted it was a PMTU blackhole, not DPI), and what re-opens it.


## v0.4.1 — 2026-07-28

macOS call audio. No Rust code changed: the fix is in the `veil_media` Flutter
plugin, which is built by its own script rather than by cargo.

### Fixed

- **Calls on macOS had no audio in either direction.** The audio device module
  applies the app's stored microphone preference with `setDeviceID:` on the
  input node's `AUAudioUnit`. That property is only settable while the unit
  holds no render resources, and merely READING `engine_.inputNode` a few lines
  earlier already allocates them — so the setter returned -10851
  (`kAudioUnitErr_InvalidPropertyValue`) every single time. The failure was
  logged and ignored, but it left the input unit unable to initialise, and
  because the node stays in the graph the whole engine then failed to start
  with -10875 (`kAudioUnitErr_FailedInitialization`). Playout died with it,
  though playout does not depend on the input device at all, and every API
  still reported success: `mic permission=true`, `startAudio=true`.

  Measured on a Mac↔Android p2p call: 0.2 packets/s of 32-byte DTX comfort
  noise from the Mac against the 50 packets/s of real Opus the phone was
  sending, with the Mac's jitter buffer growing past four seconds. After the
  fix both directions carry 50.6 and 50.7 packets/s with buffers steady at
  53 ms and 49 ms.

  Three parts: deallocate the input unit's render resources before setting the
  device; on failure fall back to the system default rather than insisting on a
  device the unit refused; and if the engine still will not start, rebuild it
  once from scratch, because a poisoned input unit stays in the graph and
  restarting the same engine fails identically.

### Note for macOS builders

`libveil_media.dylib` is gitignored and bundled from
`flutter/veil_media/macos/Frameworks/`, so a checkout that never runs
`macos/build_veil_media_dylib.sh` keeps whatever binary is already sitting
there. The copy on the machine where this was found was four days older than
the sources, and nothing in the build output said so.

## v0.4.0 — 2026-07-28

Feature release with security fixes. Two API changes make this a minor bump on
the 0.x line rather than a patch.

### Security

An audit of the transport, session and mesh layers found six defects. All are
fixed here, each with a regression test verified against the broken code.

- **Media injected into an encrypted call.** `dispatch_inbound_auto` decided
  whether a leg was encrypted from the packet's own leading bytes: anything not
  carrying the seal took the legacy passthrough straight to the receive
  callback. The relay path deliberately does not re-wrap media in a fresh
  ML-KEM envelope, so on that leg the seal is the only thing authenticating the
  sender, and the sender id on the Forward frame is not authenticated — anyone
  on the call path could drop raw RTP into a live call, past both the AEAD and
  the replay window. The cipher is now resolved from the registry before the
  branch, so the decision comes from our own state. Channels with no keys keep
  the legacy ingress unchanged.
- **Unbounded broadcast dedup set.** `BROADCAST_SEEN_CAP` gated the TTL sweep
  but never the insert, so a peer minting distinct keys faster than the 10 s TTL
  expired them grew the map without limit — and the O(n) sweep then ran on every
  frame while holding the dispatcher's route-cache write lock. The cap now
  evicts, batched so the scan amortises to O(1) per frame.
- **Reassembly fairness quota defeated two ways.** The per-sender caps were
  checked only when a transfer was created, so a sender could open its full slot
  allowance with 1-byte chunks and then grow each transfer until it owned the
  whole 64 MiB budget; and the quota was keyed on `sender_node_id`, a cleartext
  field of a relayed envelope. Byte quotas now bind on every insertion, and a
  second, deliberately looser quota is keyed on the authenticated previous hop.
- **Signed beacons were replayable for the skew window.** Accepting a beacon
  ends in an unconditional re-register of the source's link at the datagram's
  source address, and the only guard was a per-source rate window. A
  byte-identical capture re-sent from another address repointed the victim's
  link at the replayer for up to 120 s. Signed beacons now carry their
  authenticated content in a replay set for exactly that window.
- **Beacon per-subnet slot cap could stay stuck.** It refused a new address
  without first sweeping expired slots, unlike the global cap beside it, so an
  attacker holding 64 addresses in one /24 locked out every new address from
  that subnet — on a LAN mesh, that is the legitimate neighbours.
- **FFI handle generation escaped its field.** The slot counter is a `u32` but
  the token carries only 16 generation bits on 32-bit hosts, so after 65535
  reuses of one slot every token that slot issued failed validation for good.

### Added

- Anonymous sends spread a fragmented by-identity transfer across a service's
  own provider slots, and `AuthAppDeliver` can carry several reply blocks so a
  fragmented reply can spread too. Together these lift the single-relay ceiling
  on shared-folder throughput.
- Managed packet tunnels for Android, Apple, Windows and Linux, per-application
  VPN routing on Android, and oproxy failover preserved through the Apple
  tunnel.
- Explicit call-path hole punching with typed outcomes, direct-session
  re-establishment on network change, and tolerance for coordinators that
  predate punch tokens.
- Signed public-space DHT records; macOS window sharing; mid-call video bitrate
  retuning with sender-leg metrics.

### Changed

- **Breaking:** `AuthAppDeliver.reply_block: Option<ReplyBlock>` is now
  `reply_blocks: Vec<ReplyBlock>`. The presence byte became a count, so the
  encodings for zero and one block are byte-identical to before; only a genuine
  multi-block envelope differs. Capped at decode.
- **Breaking:** `EnvelopeChunkReassembler::add` takes the authenticated peer id.
- Relay entry verification and anonymous-send resolution are cached, and a
  stored record's signature is no longer verified twice.
- The Linux VPN helper validates its config by open handle rather than by path,
  and `O_NOFOLLOW` refuses a symlink at that path. It runs as root under pkexec
  while the path lives in a directory the invoking user controls, so the
  previous stat-then-read let that user swap what the two calls saw.

### Fixed

- SOCKS dialing is bounded so a silent proxy cannot wedge peer dialing, and the
  RTT probe table is bounded against growth from inbound frames.
- The Falcon private key is kept out of logs and freed memory.
- A service no longer resolves its own registration when it is the host.
- Assorted media and mobile-lifecycle fixes: ADM capture start failures are
  surfaced on both paths, stale realtime stream fallback is bounded, older
  packet-sizing ABIs are tolerated, dynamic-lookup imports stay out of the macOS
  dylib exports, and the QR scanner moved to Apple Vision.

`veilclient-ffi` remains on its independent 0.4.x ABI line, `veil-onion-stream`
on its 0.1.x line and `veil-vpn-helper` on its 0.1.x line.

## v0.3.1 — 2026-07-16

Corrective release. The v0.3.0 tag accidentally omitted a signed feature tail
that xVeil already depended on; this release restores that history while
retaining the Rust 1.97, Windows, and poisoned-lock fixes shipped in v0.3.0.

- Restored direct-P2P/relay call routing, full-frame VP8 transport, latency and
  media diagnostics, voice messages, video notes, and group-media support.
- Restored the iOS media plugin integration and mobile lifecycle fixes.
- Restored sovereign recovery, headless Dart/FFI support, and authenticated
  real-time transport APIs.
- Restored onion-provider isolation, capability negotiation, delivery retries,
  and the associated runtime hardening.
- Regenerated the feature-gated C header and aligned the restored tail with the
  Rust 1.97 warning policy across the workspace, embedded FFI, and simulations.

`veilclient-ffi` remains on its independent 0.4.x ABI line and
`veil-onion-stream` remains on its independent 0.1.x line.

## v0.3.0 — 2026-07-15

Feature release covering the signed `main` history after v0.2.0.

- Added the embedded, diskless node lifecycle and mobile FFI configuration
  path used by Flutter on Android, iOS, macOS, and Linux.
- Added authenticated offline mailbox sealing, relay replication, fetch/ACK,
  recovery, and sender verification across the Rust, C, and Dart APIs.
- Added reliable anonymous streams, low-latency media channels, and direct-P2P
  media with policy-controlled relay/onion routing.
- Added sovereign identity operations and cumulative-PoW nickname claim and
  resolution APIs.
- Hardened relay discovery, rendezvous registration, circuit recovery, queue
  pressure, and cold-start behavior; leaf deployments are relay-capable by
  default, with operational playbooks for staged rollout.
- Updated `anyhow` to 1.0.103, `crossbeam-epoch` to 0.9.20, and
  `quinn-proto` to 0.11.15, and aligned Android builds on API 24.
- Restored the zero-warning Rust 1.97 gate and made the Unix-only TCP MSS
  clamp a safe no-op on Windows.

`veilclient-ffi` remains on its independent 0.4.x ABI line and the new
`veil-onion-stream` crate remains on its independent 0.1.x line.

## v0.2.0 — 2026-06-14

Minor release. Bundles everything on `main` since v0.1.1 (≈330 commits) plus the
2026-06-14 audit-remediation batch below. **Breaking** vs v0.1.1 (hence the
minor bump, pre-1.0 semver):

- **FFI ABI** — all caller-supplied text inputs migrated to the explicit
  `(ptr, len)` C ABI; the deprecated NUL-terminated phrase entry-points were
  removed. `veilclient-ffi` is at 0.4.0. Regenerate bindings against the shipped
  `veil_ffi.h`.
- **Config** — the dead `gateway_failover_delay_secs` knob was removed; configs
  that set it must drop the key (strict validation rejects unknown keys).
- **Flutter plugin** — `connect` / `restoreIdentity` / stream `read` now run on
  a worker isolate (ANR fix); Dart bindings moved to the explicit-length ABI.

Auto-update: `min_compatible_version = 0.1.1` (the updater swaps the binary;
any install ≥ 0.1.1 may apply this update).

### Audit-remediation batch 2026-06-14 (full-project audit + external report merge)

A full-project security/quality audit cross-validated against an external
report. Validated findings fixed brick-by-brick (clippy `-D warnings` + tests
each commit); already-handled items and false positives recorded, design-heavy
items deferred with a re-open trigger (see `TASKS.md`).

- **lazy-miner never terminates** (F-CRYPTO-1/2) — the background nonce miner
  ground a core indefinitely toward an unreachable difficulty cap (~40% idle
  CPU). Added a full-2³²-nonce-space exhaustion guard + single-sourced the cap
  default (was a hardcoded 64); testnet idle CPU dropped from ~40% to <1%.
- **DHT dead code + foot-gun** (DHT F1/F2/F3) — deleted three unused network
  methods (one returned an *unverified* value), an always-false replica-store
  disjunct, and corrected iterative-filter doc-drift.
- **introduce decode hardening** (Anon F3) — `IntroducePayload::decode` now
  requires exact length, rejecting smuggled trailing bytes.
- **precise rendezvous logging** (Anon F4) — a known-cookie replay/drop is no
  longer mislabelled `cookie_unknown`; the anti-probe signal fires only on a
  genuinely unrecognised cookie.
- **onion path diversity** (M-1) — onion middle-hops and the non-pinned
  rendezvous relay are now drawn at random (was deterministic, concentrating
  traffic and making paths predictable); operator-pinned relays stay ordered.
- **reload-zombie guard** (M-2) — config reload now dry-runs each listener's
  transport URI + context *before* tearing tasks down, closing an
  online-but-dead state on a malformed listen config.
- **interrupt-flag race** (F-CRYPTO-3) — the Ctrl-C PoW-interrupt flag and its
  handler are now installed atomically (single `get_or_init`), so a concurrent
  first-call can't decouple them.
- **obfs4 handshake over-read** (obfs4 F2) — documented the no-pipeline
  invariant + debug-assert it; the truncate path can no longer silently drop
  bytes if framing ever changes.
- **misc** — FFI test CString leak reclaimed; ticket fast-path
  `verified_membership_cert` comment corrected (IPC-status completeness, not a
  security gap).

## Audit batch 2026-06-02 (workspace security + code-quality)

Full-workspace audit of `veil-*` + `veilcore` + `veilclient`,
cross-referenced with a second independent audit report; the union of confirmed
findings was fixed. **Two wire-format changes this batch** (unlike K–P): the
obfs4 ntor handshake shrank by 8 bytes (C-01) and `DeliveryStatusPayload` grew
from 33 to 65 bytes (C-09) — see the per-finding notes.

- **C-01 obfs4 anti-DPI** (`04332d3`) — removed the plaintext 8-byte timestamp
  from the obfs4 ntor handshake (a static DPI distinguisher) and bound the
  epoch-hour into the handshake MAC instead; the receiver accepts a small window
  of candidate epochs for clock skew. `HANDSHAKE_MIN_BYTES` shrank by 8.
- **C-02 / dead code** (`c438de6`) — deleted unused `veil-obfs4::tls_prefix`
  (200 LOC, wired into no transport) and three doc-only `veilcore::node`
  modules (`e2e` / `util` / `battery`).
- **C-03 mesh beacon secure-by-default** (`c7fc064`) — `require_signed_beacons`
  now defaults **true** (unsigned beacons dropped, closing on-link
  gateway-injection / neighbor-redirect); role flags are no longer advertised
  unless the new `advertise_role_in_beacon` is set (default false), so a passive
  on-link observer can't fingerprint gateways/relays.
- **C-04 exit-proxy SSRF** (`fe462fa`) — `is_forbidden_destination` now also
  rejects IPv4-compatible `::x.x.x.x` and CGNAT `100.64.0.0/10` destinations
  (the `::x.x.x.x` form is non-routable on modern Linux; CGNAT was the routable
  residual).
- **C-06 FIND_VALUE node-ids-only** (`c438de6`) — the closest-nodes fallback no
  longer inlines transports; the requester re-resolves via `ResolveTransport`,
  closing the value-lookup routing-graph leak (matching FIND_NODE V2). Guarded by
  a 64-node linear-chain regression (`dc73958`) proving endpoint discovery still
  converges with node-id-only responses.
- **C-09 authenticated DELIVERED ACK** (`3723371`, `cf766af`) — the recipient
  now MACs the `content_id` under a per-message ACK key derived from the E2E
  ML-KEM shared secret (`veil_e2e::derive_ack_key`); the originator credits
  delivery reputation only when the MAC verifies, so an on-path relay can no
  longer forge ACKs to inflate a peer's reputation. `DeliveryStatusPayload`
  33 → 65 bytes (the 32-byte MAC; all-zero on non-E2E / legacy, which earns no
  reputation).
- **C-10 bootstrap dial cap** (`596eef8`) — `MAX_BOOTSTRAP_SEEDS_PER_SOURCE = 32`
  on both the HTTPS and DNS seed loops (startup-amplification / DoS bound).
- **C-12 secret redaction** (`596eef8`) — `IdentityConfig` / `MetricsConfig`
  `Debug` impls no longer print key material.
- **C-14 PSK at-rest** (`596eef8`) — PSK files written `0600` via atomic
  write-then-rename.
- **C-15 pairing document verification** (`3b30cf2`) — the pairing target now
  runs `verify_identity_document` on the received document (node_id↔master
  binding + the master-cert chain over the appended subkeys), not just a node_id
  match; `PairingTarget` carries `now_unix` for the validity-window check.
- **C-16 hybrid verify** (`fe462fa`) — Ed25519+Falcon hybrid verify arms delegate
  to `veil_crypto::verify_message` instead of an open-coded path.
- **U1 hybrid DELETE** (`fe462fa`) — DHT `handle_delete` accepts all wire algos
  (0–4) via `SignatureAlgorithm::from_wire_byte`; the DeletePayload pubkey cap is
  `MAX_SIGNATURE_PUBKEY_BYTES` (was the ML-KEM cap).
- **U2 durable-snapshot scope** (`59cec93`) — the DHT JSON value snapshot writes
  the hot tier only when the cold tier is durable (RocksDB), avoiding a redundant
  re-dump of already-persisted records; it still takes a full snapshot for the
  in-memory cold tier.
- **U3 IPC stream window** (`fe462fa`) — the initial stream window is clamped to
  `MAX_STREAM_INITIAL_WINDOW = 16 MiB` (peer-driven memory-DoS bound).
- **U4 config round-trip** (`fe462fa`) — fixed `SessionConfig::is_default` so
  non-default session knobs survive a serialize → deserialize cycle.

Docs synced in `ab8de0e` (config-reference, ARCHITECTURE_FULL, protocol-spec;
en + ru).

## Audit batch 2026-05-25 (Phases K — P)

Cross-audit follow-up: 26 findings closed, 10 verified false positives,
2 documented-design choices. No new wire-protocol bumps; all changes
are defensive hardening visible only on adversary-shaped input.

- **Phase K** (`a208737`) — gitignore stend secrets; clippy `await_holding_lock`
  attributes on phase650b serialization tests.
- **Phase L** (`3d698f9`) — DHT `find_value` filter consistency with `find_node`;
  Argon2 product cap `MAX_KDF_PRODUCT_KIB = 256 GiB·iter`; admin request
  DoS cap `MAX_ADMIN_REQUEST_BYTES = 64 KiB`; verified e2e ML-KEM HKDF
  binding already covers `dst_id` (audit FP).
- **Phase M** (`705a9ce`) — 8 medium/low findings: Falcon-512 pk size
  invariant via unconditional check; pair_transport frame-oversized
  runtime guard; cursor `read_array<N>` checked_add; obfs4 compile-time
  invariants + pad-len comment rewrite; lookup_cache TTL operator unify;
  identity/verify tautological magic check removed; AppHandle::into_split
  preserves inbound_streams_rx.
- **Phase N** (`c388b19`) — anycast per-record TTL enforcement on resolve:
  `TieredStore::get_with_meta` exposing inserted_at; `resolve_internal`
  filters expired records.
- **Phase O** (`0a8ff0c`) — signed anycast IPC advertise: daemon auto-signs
  anycast records via `SovereignIdentity::ed25519_signing_key()`.
- **Phase P** (`56a76b1`) — 4 defense-in-depth fixes:
  `MetricsConfig` deny_unknown_fields; bootstrap clock-broken fail-closed;
  FCM `expires_in` clamped to `[60, 7200] s`; update-manifest `issuer_pk`
  per-algorithm caps (Ed25519=128 / Falcon-512=1280 / Hybrid=1408 B).

## Wave 1: Scalable Routing (Epics 294-323)

- **294** DHT-routed forwarding: RecursiveRelay O(log N) hop delivery; gossip TTL reduced to 2
- **300** Adaptive routing parameters: K, TTL, fan-out, cache size derived from estimated network size N
- **301** Gossip suppression: proactive gossip replaced by reactive DHT forwarding
- **302** Session pooling: max_concurrent 65K; tx_queue_depth 1024; session hibernate + LRU eviction
- **303** Tiered DHT store: hot/cold HashMap tiers; configurable max_store_entries (1M default)
- **304** Adaptive PoW: epoch-based difficulty; VDF alternative; backward-compatible priority tiers
- **305** Protocol versioning: forward-compatible dispatch; TLV extension; MIN_CORE_ROUTER_MINOR
- **310** Core role with K=40, full routing table, sketch buckets for far keyspace
- **311** Proximity-aware routing: Vivaldi bias in iterative lookup; RTT-based forward scoring
- **312** Compact routing state: sketch buckets (1 contact) for far k-buckets; Core enables at threshold 128
- **313** Mailbox sharding: shard_key-based replica selection; global 100K message cap
- **320** DHT keyspace sharding: 256 shards, 16 per node; shard-aware STORE filtering; rebalancing on join/leave
- **321** Bandwidth-aware transit: congestion backpressure (>78% → drop); adaptive epidemic fan-out
- **322** Reputation system: uptime + relays + vouches; transit gate (200 points); DHT attestation wire format
- **323** Memory budget manager: 256MB default; priority-based component eviction

## Security Hardening (Epics 172-174)

- **172** Sybil/Eclipse/Flood/Replay/Spoofing mitigations
- **173** Mailbox quota fixes (store_forward bypass, quota release)
- **174** Peer nonce auto-update on re-mine

## Code Quality (Epic 306)

- **306** Full codebase audit: 2 CRITICAL (key leak in Debug output) fixed; 3 MEDIUM accepted
