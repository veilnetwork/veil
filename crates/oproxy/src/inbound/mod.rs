//! Inbound listeners — the client-side surfaces that accept local
//! TCP connections in а given protocol (SOCKS5 / HTTP CONNECT / TProxy),
//! extract the destination `(host, port)`, и hand the connection off
//! к [`crate::connector::open_stream_and_bridge`].

pub mod http;
pub mod socks5;
pub mod tproxy;

// Audit batch 2026-05-23: dropped `target_os = "freebsd"` gate because
// the FreeBSD code paths (`ipfw fwd` + `getpeername`) were stubs that
// returned а runtime error from the first accept.  Linux-only build
// surface matches the only platform where TProxy actually works.
#[cfg(target_os = "linux")]
pub(crate) mod tproxy_unix;
