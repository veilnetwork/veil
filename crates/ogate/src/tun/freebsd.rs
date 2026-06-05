//! TUN device for FreeBSD via raw `/dev/tun*` + `TUNSIFHEAD` ioctl.
//!
//! FreeBSD prepends a 4-byte address-family header on each packet by
//! default. We disable that with `TUNSIFHEAD = 0` so reads/writes carry
//! plain IPv4 / IPv6 packets — matching the Linux IFF_NO_PI mode.
//!
//! Address / MTU / up are applied through `ifconfig` rather than direct
//! `SIOCSIFADDR` / `SIOCSIFFLAGS` ioctls. Two reasons:
//! * ifconfig is bundled into every FreeBSD base system, so no extra
//!   tooling is required at runtime.
//! * The struct layout for `ifreq` differs across architectures and the
//!   nix crate's coverage is thin on the FreeBSD side; replicating
//!   ifconfig's logic is far more code than it is worth.
//!
//! `iface_name` is required to be a `tunN` form (kernel-assigned), so
//! the code opens `/dev/<iface_name>` directly. If you want a friendlier
//! name (e.g. `ogate0`), run `ifconfig tunN name ogate0` after startup.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::io::FromRawFd;
use std::sync::Arc;

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use tokio::io::unix::AsyncFd;

use super::{TunError, run_cmd};
use crate::config::OgateConfig;

// TUNSIFHEAD is _IOW('t', 96, int) — set the IFHEAD mode (prepend AF
// header on reads/writes when non-zero). We disable it.
nix::ioctl_write_ptr!(tunsifhead, b't', 96, i32);

pub struct Device {
    inner: Arc<AsyncFd<OwnedFd>>,
    iface_name: String,
}

impl Device {
    pub async fn new(cfg: &OgateConfig) -> Result<Self, TunError> {
        if !cfg.iface_name.starts_with("tun") {
            return Err(TunError::Setup(format!(
                "FreeBSD: iface_name must start with 'tun' (got {:?}). \
                 Use 'ifconfig tunN name <friendly>' after startup if needed.",
                cfg.iface_name
            )));
        }
        let path = format!("/dev/{}", cfg.iface_name);
        let fd = open(
            path.as_str(),
            OFlag::O_RDWR | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|e| TunError::Setup(format!("open {path}: {e}")))?;
        // SAFETY: nix::fcntl::open returns a valid, owned RawFd we have not duped.
        let owned: OwnedFd = unsafe { OwnedFd::from_raw_fd(fd) };

        // Switch to raw-IP mode (drop 4-byte AF header).
        let mut zero: i32 = 0;
        // SAFETY: fd is open, owns the descriptor; pointer is to a stack int.
        unsafe {
            tunsifhead(owned.as_raw_fd(), &mut zero as *mut i32 as *const i32)
                .map_err(|e| TunError::Setup(format!("TUNSIFHEAD: {e}")))?;
        }

        // ifconfig setup: address, MTU, up.
        let prefix = cfg.prefix_v4;
        if let Some(v4) = cfg.local_addr_v4 {
            let cidr = format!("{v4}/{prefix}");
            run_cmd(
                "ifconfig",
                &[
                    &cfg.iface_name,
                    "inet",
                    &cidr,
                    "mtu",
                    &cfg.mtu.to_string(),
                    "up",
                ],
            )?;
        }
        if let Some(v6) = cfg.local_addr_v6 {
            let cidr = format!("{v6}/{}", cfg.prefix_v6);
            if let Err(e) = run_cmd("ifconfig", &[&cfg.iface_name, "inet6", &cidr, "alias"]) {
                tracing::warn!(error = %e, "freebsd ipv6 alias failed (continuing v4-only)");
            }
        }

        let async_fd = AsyncFd::new(owned).map_err(TunError::Io)?;

        // Audit batch 2026-05-24: NO Mutex wrap.  `AsyncFd::readable()` и
        // `AsyncFd::writable()` are independent — both can have in-flight
        // waiters on the same `&AsyncFd` simultaneously, и `try_io`
        // re-checks the OS-level state per call.  The previous Mutex was
        // а **read/write deadlock** — reader.lock() blocked across
        // `readable().await`, starving the writer until а packet
        // arrived, и vice versa.
        Ok(Self {
            inner: Arc::new(async_fd),
            iface_name: cfg.iface_name.clone(),
        })
    }

    pub fn name(&self) -> &str {
        &self.iface_name
    }

    pub fn split(self) -> (Reader, Writer) {
        let r = Reader {
            inner: Arc::clone(&self.inner),
        };
        let w = Writer {
            inner: Arc::clone(&self.inner),
        };
        (r, w)
    }
}

pub struct Reader {
    inner: Arc<AsyncFd<OwnedFd>>,
}

impl Reader {
    /// Read the next IP packet от the TUN device into а new Vec.
    pub async fn read_packet(&mut self) -> std::io::Result<Vec<u8>> {
        self.read_packet_with_prefix(0).await
    }

    /// Read the next IP packet into а Vec що has `prefix` uninit bytes
    /// reserved at the start (matches `standard.rs::Reader` API so the
    /// bridge can call `read_packet_with_prefix(APP_IPC_SEND_PREFIX_BYTES)`
    /// uniformly across all platforms).  Audit batch 2026-05-24: added к
    /// close the FreeBSD-specific compile-break где bridge.rs invoked а
    /// method що did not exist on this backend.
    pub async fn read_packet_with_prefix(&mut self, prefix: usize) -> std::io::Result<Vec<u8>> {
        // 65_535 = max IP datagram size; FreeBSD `/dev/tun` returns one
        // packet per read когда TUNSIFHEAD=0 (raw mode).
        const PKT_CAP: usize = 65_535;
        let total = prefix + PKT_CAP;
        let mut buf = vec![0u8; total];
        loop {
            let mut guard = self.inner.readable().await?;
            let fd_raw: RawFd = self.inner.get_ref().as_raw_fd();
            match guard.try_io(|_| {
                // SAFETY: fd is owned by the AsyncFd; the slice covers
                // valid initialised buffer bytes.
                let n = unsafe {
                    libc::read(
                        fd_raw,
                        buf[prefix..].as_mut_ptr() as *mut libc::c_void,
                        PKT_CAP,
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    buf.truncate(prefix + n);
                    return Ok(buf);
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }
}

pub struct Writer {
    inner: Arc<AsyncFd<OwnedFd>>,
}

impl Writer {
    /// Write а full IP packet к the TUN device.
    ///
    /// Treats а short write as `WriteZero` (previously а partial write
    /// returned `Ok(())`, silently truncating the IP datagram on the
    /// wire which would corrupt headers и cause client confusion). TUN
    /// on FreeBSD historically writes atomically (one packet = one
    /// write syscall); а short return value indicates kernel pushback
    /// или а driver bug — best к surface it as an error rather than
    /// swallow it.
    pub async fn write_packet(&mut self, packet: &[u8]) -> std::io::Result<()> {
        loop {
            let mut guard = self.inner.writable().await?;
            let fd_raw: RawFd = self.inner.get_ref().as_raw_fd();
            match guard.try_io(|_| {
                let n = unsafe {
                    libc::write(fd_raw, packet.as_ptr() as *const libc::c_void, packet.len())
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(written)) => {
                    if written == packet.len() {
                        return Ok(());
                    }
                    // Partial write — TUN packets must be written atomically.
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        format!(
                            "TUN partial write: wrote {} of {} bytes — packet corrupted",
                            written,
                            packet.len(),
                        ),
                    ));
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }
}
