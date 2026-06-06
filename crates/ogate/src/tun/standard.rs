//! TUN device for Linux / macOS / Windows via the `tun` crate.
//!
//! The `tun` 0.6 crate handles IPv4 address + netmask + bringing the
//! device up via OS-specific ioctls / WinTun. IPv6 is added via a
//! shell-out to `ip` / `ifconfig` / `netsh` because the crate's API
//! does not expose it portably.

use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

use super::{TunError, run_cmd};
use crate::config::OgateConfig;

/// Owning handle to the TUN device. Split into reader/writer halves via
/// [`Device::split`] which calls `tokio::io::split` so reads and writes
/// progress independently without a userspace mutex coordinating them.
pub struct Device {
    dev: tun::AsyncDevice,
    iface_name: String,
    mtu: u16,
}

impl Device {
    /// Create + configure the device from `cfg`.
    ///
    /// On Linux this opens `/dev/net/tun` with `TUNSETIFF` (IFF_TUN | IFF_NO_PI).
    /// On macOS this allocates a `utun` device. On Windows this uses WinTun.
    pub async fn new(cfg: &OgateConfig) -> Result<Self, TunError> {
        let local_v4 = cfg
            .local_addr_v4
            .ok_or_else(|| TunError::Setup("local_addr_v4 missing".into()))?;
        let mask = netmask_from_prefix_v4(cfg.prefix_v4);

        let mut tun_cfg = tun::Configuration::default();
        tun_cfg
            .name(&cfg.iface_name)
            .address(local_v4)
            .netmask(mask)
            .mtu(cfg.mtu as i32)
            .up();

        let dev = tun::create_as_async(&tun_cfg)
            .map_err(|e| TunError::Setup(format!("tun create: {e}")))?;

        // IPv6 address (optional) via shell-out.
        if let Some(v6) = cfg.local_addr_v6
            && let Err(e) = add_ipv6(&cfg.iface_name, v6, cfg.prefix_v6)
        {
            tracing::warn!(error = %e, "ipv6 setup failed (continuing v4-only)");
        }

        // macOS v4 routing. The `tun` crate sets the interface address, but
        // macOS does NOT auto-install a route to the virtual-LAN peers over a
        // point-to-point utun (Linux gets a connected route for free from the
        // address+netmask). Without it, packets to a peer's `addr_v4` fall
        // through to the default gateway (en0) and never reach the veil.
        //
        // We (1) re-assert the local address as a /32 — a connected route for
        // the configured `prefix_v4` would hijack an overlapping *physical*
        // LAN (e.g. a 192.168.0.0/16 ogate net on a host whose Wi-Fi is
        // 192.168.1.x), and (2) add an explicit host route per configured peer
        // through the utun. Host routes are collision-proof: they only capture
        // the exact peer addresses, never a broad subnet.
        #[cfg(target_os = "macos")]
        {
            let iface = cfg.iface_name.as_str();
            let local = local_v4.to_string();
            // local==dest for the P2P utun; reachability is driven by the
            // per-peer routes below, not by the interface's own prefix.
            run_cmd(
                "ifconfig",
                &[
                    iface,
                    "inet",
                    &local,
                    &local,
                    "netmask",
                    "255.255.255.255",
                    "up",
                ],
            )?;
            for peer in &cfg.peers {
                if let Some(paddr) = peer.addr_v4 {
                    let paddr_s = paddr.to_string();
                    if let Err(e) = run_cmd(
                        "route",
                        &["-n", "add", "-host", &paddr_s, "-interface", iface],
                    ) {
                        // A duplicate route on restart (or a transient failure)
                        // must not abort bring-up — log and continue.
                        tracing::warn!(error = %e, peer = %paddr_s, iface,
                            "macos: add host route to peer failed (continuing)");
                    }
                }
            }
        }

        Ok(Self {
            dev,
            iface_name: cfg.iface_name.clone(),
            mtu: cfg.mtu,
        })
    }

    pub fn name(&self) -> &str {
        &self.iface_name
    }

    /// Split into independent reader / writer halves via `tokio::io::split`.
    /// MTU is passed to the reader so each TUN read allocates exactly
    /// `mtu + headroom` bytes instead of a fixed 64 KiB.
    pub fn split(self) -> (Reader, Writer) {
        let (r, w) = tokio::io::split(self.dev);
        let read_size = self.mtu as usize + READ_HEADROOM;
        (
            Reader {
                inner: r,
                read_size,
            },
            Writer { inner: w },
        )
    }
}

/// Extra bytes allocated above the configured MTU per TUN read.  Covers
/// possible IPv6 extension-header growth, kernel pad, and future MTU
/// raise-without-restart races.  256 bytes is a single TLB line on most
/// archs so overhead is negligible.
const READ_HEADROOM: usize = 256;

/// macOS utun prepends a 4-byte address-family header (big-endian) to every
/// packet — `AF_INET` (2) for IPv4, `AF_INET6` (30) for IPv6 — and expects the
/// same on write. The `tun` 0.6 crate exposes this via `has_packet_information`
/// but neither strips nor adds it, so ogate must. Linux (`/dev/net/tun` with
/// `IFF_NO_PI`) carries raw IP and needs none of this — hence the `cfg`.
#[cfg(target_os = "macos")]
const MACOS_UTUN_PI_LEN: usize = 4;
#[cfg(target_os = "macos")]
const MACOS_UTUN_PI_AF_INET: [u8; 4] = [0, 0, 0, 2];
#[cfg(target_os = "macos")]
const MACOS_UTUN_PI_AF_INET6: [u8; 4] = [0, 0, 0, 30];

pub struct Reader {
    inner: ReadHalf<tun::AsyncDevice>,
    /// Per-read buffer size: `mtu + READ_HEADROOM`.  Replaces the old
    /// fixed 64 KiB `vec![0u8; 65_535]`, which for MTU 16 000 wasted ~50 KiB
    /// of zero-fill per packet.
    read_size: usize,
}

impl Reader {
    /// Read the next IP packet from the device.
    ///
    /// Allocates `mtu + headroom` per read (vs. the prior fixed 64 KiB
    /// `vec![0u8; 65_535]`) and uses `read_buf` to elide the zero-fill —
    /// kernel writes exactly `n` valid bytes; the uninit tail beyond `n`
    /// is dropped by `truncate(n)` before the Vec leaves the function.
    pub async fn read_packet(&mut self) -> std::io::Result<Vec<u8>> {
        self.read_packet_with_prefix(0).await
    }

    /// Read the next IP packet into a Vec that has `prefix` zero-filled bytes
    /// reserved at the start.  Returned layout:
    /// ```text
    ///   [0..prefix]            zero-filled — caller overwrites these later
    ///   [prefix..prefix + n]   kernel-written IP packet bytes
    /// ```
    /// `n` is the actual TUN read length.  The capacity beyond
    /// `prefix + n` is dropped via `truncate`.  The returned `Vec` is fully
    /// initialised — no caller can observe uninitialised heap bytes.
    ///
    /// Use this on hot paths where the consumer (e.g. SDK
    /// `send_prepared_app_ipc_send`) wants to prepend an IPC frame header
    /// without copying the data: caller writes into `[0..prefix]` in place,
    /// then forwards the full Vec to the writer task — zero memcopies of
    /// the IP-packet body.
    pub async fn read_packet_with_prefix(&mut self, prefix: usize) -> std::io::Result<Vec<u8>> {
        let cap = prefix + self.read_size;
        // Audit M1: zero-initialise the whole buffer instead of `set_len`
        // over uninitialised capacity. The previous `unsafe { set_len(cap) }`
        // both (a) handed safe callers a `Vec` whose `[0..prefix]` bytes were
        // uninit-from-malloc — a memory-disclosure footgun the moment any
        // caller read/cloned/logged the prefix before filling it — and
        // (b) constructed `&mut buf[prefix..]` over uninitialised memory to
        // hand to `read`, which is itself unsound (a `&mut [u8]` must point at
        // initialised bytes). Zeroing keeps the body zero-copy — the kernel
        // `read` overwrites `[prefix..prefix+n]` in place — at the cost of one
        // memset of an MTU-sized buffer per packet, negligible next to the
        // per-packet AEAD/TLS work downstream.
        let mut buf = vec![0u8; cap];
        let n = self.inner.read(&mut buf[prefix..]).await?;
        // macOS utun: drop the leading 4-byte address-family header so callers
        // see raw IP (matching the Linux IFF_NO_PI path). Shift the IP body left
        // over the stripped header, preserving the caller's `[0..prefix]`.
        #[cfg(target_os = "macos")]
        {
            if n >= MACOS_UTUN_PI_LEN {
                buf.copy_within(prefix + MACOS_UTUN_PI_LEN..prefix + n, prefix);
                buf.truncate(prefix + (n - MACOS_UTUN_PI_LEN));
            } else {
                // Runt read with no IP payload — return just the reserved prefix.
                buf.truncate(prefix);
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            buf.truncate(prefix + n);
        }
        Ok(buf)
    }
}

pub struct Writer {
    inner: WriteHalf<tun::AsyncDevice>,
}

impl Writer {
    /// Write one IP packet to the device.
    ///
    /// TUN semantics: one `write` = one IP packet. A short return is a boundary
    /// error, NOT a chance to retry — looping `write_all` would glue the tail of
    /// one packet onto the head of the next and desync the kernel's IP framing.
    /// Phase E27: replace `write_all` with single-call + length assert so the
    /// 16K MTU cliff surfaces honestly instead of being papered over by silent
    /// partial writes.
    pub async fn write_packet(&mut self, packet: &[u8]) -> std::io::Result<()> {
        // macOS utun expects a 4-byte address-family header (derived from the
        // IP version) prepended to each packet; Linux writes raw IP. Build the
        // exact frame to write, then do the single write + boundary check once.
        #[cfg(target_os = "macos")]
        let framed = {
            let af = match packet.first().map(|b| b >> 4) {
                Some(6) => MACOS_UTUN_PI_AF_INET6,
                _ => MACOS_UTUN_PI_AF_INET, // default to IPv4
            };
            let mut framed = Vec::with_capacity(MACOS_UTUN_PI_LEN + packet.len());
            framed.extend_from_slice(&af);
            framed.extend_from_slice(packet);
            framed
        };
        #[cfg(target_os = "macos")]
        let to_write: &[u8] = &framed;
        #[cfg(not(target_os = "macos"))]
        let to_write: &[u8] = packet;

        let n = self.inner.write(to_write).await?;
        if n != to_write.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "TUN partial write: wrote {n} of {} bytes (one write must equal one packet)",
                    to_write.len()
                ),
            ));
        }
        Ok(())
    }
}

fn netmask_from_prefix_v4(prefix: u8) -> std::net::Ipv4Addr {
    let mask = match prefix {
        0 => 0u32,
        p if p >= 32 => u32::MAX,
        p => !((1u32 << (32 - p)) - 1),
    };
    std::net::Ipv4Addr::from(mask)
}

fn add_ipv6(iface: &str, addr: std::net::Ipv6Addr, prefix: u8) -> Result<(), TunError> {
    let addr_cidr = format!("{addr}/{prefix}");
    #[cfg(target_os = "linux")]
    {
        run_cmd("ip", &["-6", "addr", "add", &addr_cidr, "dev", iface])?;
        run_cmd("ip", &["link", "set", iface, "up"])?;
    }
    #[cfg(target_os = "macos")]
    {
        run_cmd("ifconfig", &[iface, "inet6", &addr_cidr, "alias"])?;
    }
    #[cfg(target_os = "windows")]
    {
        let _ = (iface, addr_cidr);
        // netsh: prefer interface-name-based IP add. WinTun device name = iface_name.
        run_cmd(
            "netsh",
            &[
                "interface",
                "ipv6",
                "add",
                "address",
                &format!("interface={iface}"),
                &format!("address={addr}/{prefix}"),
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_v4_basic() {
        assert_eq!(
            netmask_from_prefix_v4(24),
            std::net::Ipv4Addr::new(255, 255, 255, 0)
        );
        assert_eq!(
            netmask_from_prefix_v4(16),
            std::net::Ipv4Addr::new(255, 255, 0, 0)
        );
        assert_eq!(
            netmask_from_prefix_v4(32),
            std::net::Ipv4Addr::new(255, 255, 255, 255)
        );
        assert_eq!(
            netmask_from_prefix_v4(0),
            std::net::Ipv4Addr::new(0, 0, 0, 0)
        );
    }
}
