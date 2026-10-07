# Veil UDP receive timestamp patch

Baseline: crates.io quinn-udp 0.5.14, archive SHA-256
`addec6a0dcad8a8d96a771f815f0eaf55f9d1805756410b39f5fa81332574cbd`.
Upstream MIT/Apache licenses and normalized manifest are retained. The Windows
dependency stays pinned to the parent lockfile baseline (windows-sys 0.60.2).

Only opt-in Linux/Android kernel receive timestamp metadata is added.
The default socket path, ECN/GSO/GRO semantics and network packets are unchanged.
Timestamp control messages require a larger ancillary buffer. Unsupported kernels
continue without timestamp metadata. Other platforms report no kernel timestamp.

Timestamp semantics: https://docs.kernel.org/networking/timestamping.html
The kernel timestamp represents a receive buffer; GRO can merge multiple
UDP datagrams, which must be marked as a shared timestamp in diagnostic output.
