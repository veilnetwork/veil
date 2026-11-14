# Android daemon resource retirement

`VeilBackground.retire()` seals daemon-service admission in this process before
requesting cleanup. It returns a `VeilBackgroundRetirement` only after the service
owners report no held wake lock or uncertain foreground state and ActivityManager
reports no foreground instance of this application's daemon component. Failure
keeps admission sealed. Repeating acquisition recovers the same process-local
operation and requires fresh observations.

`verifyReleasedResources()` rechecks those facts without starting or stopping a
service. `releaseAdmission()` permits future explicit starts; the enclosing host
must call it only after its own native erasure release and fresh-lifetime handoff.
A repeated successful release does nothing, and an old release cannot unseal a
new retirement. Tokens are random, process-local and never logged or persisted.

Start and stop intents carry an admission generation. Retirement invalidates
queued old intents even after admission is released. A delayed command cannot
tear down an already admitted replacement. A sticky callback after retirement
does not restore background work until a fresh start has been admitted. Service
creation alone no longer promotes a stale request to foreground; an admitted
start command performs promotion within the normal foreground-start deadline.

This confirms resource release and prevents reacquisition; it does not claim
that Android already called `onDestroy`, or that Rust nodes, VPNs, capture services
or other application writers have stopped. A host must retire and verify those
owners independently. This API alone never authorizes profile or OS-key deletion.

The JVM smoke in `android/src/test/kotlin/com/veil/veil_flutter/DaemonRetirementGateSmoke.kt`
runs against the actual admission class with no Android dependencies. Compile it
together with `DaemonRetirementGate.kt` and run its main function. It covers
resource refusal, lost-reply retries, stale start/stop generations and old release
tokens. Android compilation and host tests do not qualify actual lifecycle timing
or OEM behavior; an isolated device run is still required before host activation.

Platform contracts: [Service lifecycle and foreground state](https://developer.android.com/reference/android/app/Service),
[own-service observations](https://developer.android.com/reference/android/app/ActivityManager#getRunningServices(int)).
