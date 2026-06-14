//! Inbound listeners — the client-side surfaces that accept local
//! TCP connections in a given protocol (SOCKS5 / HTTP CONNECT / TProxy),
//! extract the destination `(host, port)`, and hand the connection off
//! to [`crate::connector::bridge_via_routing`].

pub mod http;
pub mod socks5;
pub mod tproxy;

// Audit batch 2026-05-23: dropped `target_os = "freebsd"` gate because
// the FreeBSD code paths (`ipfw fwd` + `getpeername`) were stubs that
// returned a runtime error from the first accept.  Linux-only build
// surface matches the only platform where TProxy actually works.
#[cfg(target_os = "linux")]
pub(crate) mod tproxy_unix;
