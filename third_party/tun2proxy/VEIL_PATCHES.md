# Veil-local tun2proxy patch

This directory vendors `tun2proxy` 0.8.2 under its existing MIT
license. The upstream crate is kept intact except for a narrow programmatic
extension used by xVeil's Android system VPN:

- `Args::proxy_selector` accepts an authenticated loopback selector service;
- each new TCP or UDP flow may select a different local SOCKS5 listener;
- selector timeout, malformed output, or a non-loopback address rejects the
  flow instead of falling back to a direct route;
- the CLI and the default single-proxy library path remain unchanged.

The selector is intentionally not exposed as a command-line option. xVeil
starts it inside `VeilVpnService` and passes its random token through the
in-process FFI call.
