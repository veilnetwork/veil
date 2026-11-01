//! Uniform interface to send and receive UDP packets with advanced features useful for QUIC
//!
//! This crate exposes kernel UDP stack features available on most modern systems which are required
//! for an efficient and conformant QUIC implementation. As of this writing, these are not available
//! in std or major async runtimes, and their niche character and complexity are a barrier to adding
//! them. Hence, a dedicated crate.
//!
//! Exposed features include:
//!
//! - Segmentation offload for bulk send and receive operations, reducing CPU load.
//! - Reporting the exact destination address of received packets and specifying explicit source
//!   addresses for sent packets, allowing responses to be sent from the address that the peer
//!   expects when there are multiple possibilities. This is common when bound to a wildcard address
//!   in IPv6 due to [RFC 8981] temporary addresses.
//! - [Explicit Congestion Notification], which is required by QUIC to prevent packet loss and reduce
//!   latency on congested links when supported by the network path.
//! - Disabled IP-layer fragmentation, which allows the true physical MTU to be detected and reduces
//!   risk of QUIC packet loss.
//!
//! Some features are unavailable in some environments. This can be due to an outdated operating
//! system or drivers. Some operating systems may not implement desired features at all, or may not
//! yet be supported by the crate. When support is unavailable, functionality will gracefully
//! degrade.
//!
//! [RFC 8981]: https://www.rfc-editor.org/rfc/rfc8981.html
//! [Explicit Congestion Notification]: https://www.rfc-editor.org/rfc/rfc3168.html
#![warn(unreachable_pub)]
#![warn(clippy::use_self)]

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::io::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsSocket;
#[cfg(not(wasm_browser))]
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

#[cfg(any(unix, windows))]
mod cmsg;

#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

#[cfg(windows)]
#[path = "windows.rs"]
mod imp;

// No ECN support
#[cfg(not(any(wasm_browser, unix, windows)))]
#[path = "fallback.rs"]
mod imp;

#[allow(unused_imports, unused_macros)]
mod log {
    #[cfg(all(feature = "direct-log", not(feature = "tracing")))]
    pub(crate) use log::{debug, error, info, trace, warn};

    #[cfg(feature = "tracing")]
    pub(crate) use tracing::{debug, error, info, trace, warn};

    #[cfg(not(any(feature = "direct-log", feature = "tracing")))]
    mod no_op {
        macro_rules! trace    ( ($($tt:tt)*) => {{}} );
        macro_rules! debug    ( ($($tt:tt)*) => {{}} );
        macro_rules! info     ( ($($tt:tt)*) => {{}} );
        macro_rules! log_warn ( ($($tt:tt)*) => {{}} );
        macro_rules! error    ( ($($tt:tt)*) => {{}} );

        pub(crate) use {debug, error, info, log_warn as warn, trace};
    }

    #[cfg(not(any(feature = "direct-log", feature = "tracing")))]
    pub(crate) use no_op::*;
}

#[cfg(not(wasm_browser))]
pub use imp::UdpSocketState;

/// Number of UDP packets to send/receive at a time
#[cfg(not(wasm_browser))]
pub const BATCH_SIZE: usize = imp::BATCH_SIZE;
/// Number of UDP packets to send/receive at a time
#[cfg(wasm_browser)]
pub const BATCH_SIZE: usize = 1;

/// Metadata for a single buffer filled with bytes received from the network
///
/// This associated buffer can contain one or more datagrams, see [`stride`].
///
/// [`stride`]: RecvMeta::stride
#[derive(Debug, Copy, Clone)]
pub struct RecvMeta {
    /// The source address of the datagram(s) contained in the buffer
    pub addr: SocketAddr,
    /// The number of bytes the associated buffer has
    pub len: usize,
    /// The size of a single datagram in the associated buffer
    ///
    /// When GRO (Generic Receive Offload) is used this indicates the size of a single
    /// datagram inside the buffer. If the buffer is larger, that is if [`len`] is greater
    /// then this value, then the individual datagrams contained have their boundaries at
    /// `stride` increments from the start. The last datagram could be smaller than
    /// `stride`.
    ///
    /// [`len`]: RecvMeta::len
    pub stride: usize,
    /// The Explicit Congestion Notification bits for the datagram(s) in the buffer
    pub ecn: Option<EcnCodepoint>,
    /// The destination IP address which was encoded in this datagram
    ///
    /// Populated on platforms: Windows, Linux, Android (API level > 25),
    /// FreeBSD, OpenBSD, NetBSD, macOS, and iOS.
    pub dst_ip: Option<IpAddr>,
    /// Optional kernel receive time in Unix nanoseconds. Available only when
    /// receive timestamp tracing is enabled on Linux/Android or Apple systems
    /// (Apple stamps have microsecond precision). A GRO buffer
    /// has one shared stamp, not a separate stamp per contained datagram.
    pub kernel_recv_unix_ns: Option<u64>,
}

impl Default for RecvMeta {
    /// Constructs a value with arbitrary fields, intended to be overwritten
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
            kernel_recv_unix_ns: None,
        }
    }
}

/// An outgoing packet
#[derive(Debug, Clone)]
pub struct Transmit<'a> {
    /// The socket this datagram should be sent to
    pub destination: SocketAddr,
    /// Explicit congestion notification bits to set on the packet
    pub ecn: Option<EcnCodepoint>,
    /// Contents of the datagram
    pub contents: &'a [u8],
    /// The segment size if this transmission contains multiple datagrams.
    /// This is `None` if the transmit only contains a single datagram
    pub segment_size: Option<usize>,
    /// Optional source IP address for the datagram
    pub src_ip: Option<IpAddr>,
}

/// Optional diagnostic hook for local errors which `UdpSocketState::send`
/// converts to success. It does not change UDP retry/error semantics. The
/// observer must not retain the borrowed transmit or expose its addresses.
#[cfg(not(wasm_browser))]
pub fn set_send_error_observer(observer: fn(&Transmit<'_>, &std::io::Error)) -> bool {
    SEND_ERROR_OBSERVER.set(observer).is_ok()
}

#[cfg(not(wasm_browser))]
type SendErrorObserver = fn(&Transmit<'_>, &std::io::Error);
#[cfg(not(wasm_browser))]
static SEND_ERROR_OBSERVER: std::sync::OnceLock<SendErrorObserver> = std::sync::OnceLock::new();

#[cfg(not(wasm_browser))]
fn observe_send_error(transmit: &Transmit<'_>, result: &std::io::Result<()>) {
    if let Err(error) = result {
        if error.kind() != std::io::ErrorKind::WouldBlock {
            if let Some(observer) = SEND_ERROR_OBSERVER.get() {
                observer(transmit, error);
            }
        }
    }
}

/// Log at most 1 IO error per minute
#[cfg(not(wasm_browser))]
const IO_ERROR_LOG_INTERVAL: Duration = std::time::Duration::from_secs(60);

/// Logs a warning message when sendmsg fails
///
/// Logging will only be performed if at least [`IO_ERROR_LOG_INTERVAL`]
/// has elapsed since the last error was logged.
#[cfg(all(not(wasm_browser), any(feature = "tracing", feature = "direct-log")))]
fn log_sendmsg_error(
    last_send_error: &Mutex<Instant>,
    err: impl core::fmt::Debug,
    transmit: &Transmit,
) {
    let now = Instant::now();
    let last_send_error = &mut *last_send_error.lock().expect("poisend lock");
    if now.saturating_duration_since(*last_send_error) > IO_ERROR_LOG_INTERVAL {
        *last_send_error = now;
        log::warn!(
            "sendmsg error: {:?}, Transmit: {{ destination: {:?}, src_ip: {:?}, ecn: {:?}, len: {:?}, segment_size: {:?} }}",
            err,
            transmit.destination,
            transmit.src_ip,
            transmit.ecn,
            transmit.contents.len(),
            transmit.segment_size
        );
    }
}

// No-op
#[cfg(not(any(wasm_browser, feature = "tracing", feature = "direct-log")))]
fn log_sendmsg_error(_: &Mutex<Instant>, _: impl core::fmt::Debug, _: &Transmit) {}

/// A borrowed UDP socket
///
/// On Unix, constructible via `From<T: AsFd>`. On Windows, constructible via `From<T:
/// AsSocket>`.
// Wrapper around socket2 to avoid making it a public dependency and incurring stability risk
#[cfg(not(wasm_browser))]
pub struct UdpSockRef<'a>(socket2::SockRef<'a>);

#[cfg(unix)]
impl<'s, S> From<&'s S> for UdpSockRef<'s>
where
    S: AsFd,
{
    fn from(socket: &'s S) -> Self {
        Self(socket.into())
    }
}

#[cfg(windows)]
impl<'s, S> From<&'s S> for UdpSockRef<'s>
where
    S: AsSocket,
{
    fn from(socket: &'s S) -> Self {
        Self(socket.into())
    }
}

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    /// The ECT(0) codepoint, indicating that an endpoint is ECN-capable
    Ect0 = 0b10,
    /// The ECT(1) codepoint, indicating that an endpoint is ECN-capable
    Ect1 = 0b01,
    /// The CE codepoint, signalling that congestion was experienced
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Create new object from the given bits
    pub fn from_bits(x: u8) -> Option<Self> {
        use EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => Ect0,
            0b01 => Ect1,
            0b11 => Ce,
            _ => {
                return None;
            }
        })
    }
}

#[cfg(all(test, unix))]
mod send_error_observer_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static OBSERVED: AtomicUsize = AtomicUsize::new(0);
    fn observer(transmit: &Transmit<'_>, error: &std::io::Error) {
        if transmit.contents.starts_with(b"observed-ignored-send") {
            assert_ne!(error.kind(), std::io::ErrorKind::WouldBlock);
            OBSERVED.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn actual_ignored_kernel_errors_are_observed_without_changing_send_policy() {
        assert!(set_send_error_observer(observer));
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let state = UdpSocketState::new((&socket).into()).unwrap();
        let mut oversized = vec![0; 65536];
        let marker = b"observed-ignored-send";
        oversized[..marker.len()].copy_from_slice(marker);
        let mut transmit = Transmit {
            destination: "127.0.0.1:9".parse().unwrap(),
            ecn: None,
            contents: &oversized,
            segment_size: None,
            src_ip: None,
        };
        assert!(state.try_send((&socket).into(), &transmit).is_err());
        assert_eq!(
            OBSERVED.load(Ordering::SeqCst),
            0,
            "try_send exposes its own errors"
        );
        state.send((&socket).into(), &transmit).unwrap();
        assert_eq!(
            OBSERVED.load(Ordering::SeqCst),
            1,
            "EMSGSIZE is still ignored but observable"
        );
        // A v4-only socket cannot send an IPv6 datagram. Exercise a second
        // error class without relying on whether a platform allows port zero.
        transmit.destination = "[::1]:9".parse().unwrap();
        transmit.contents = marker;
        assert!(state.try_send((&socket).into(), &transmit).is_err());
        state.send((&socket).into(), &transmit).unwrap();
        assert_eq!(OBSERVED.load(Ordering::SeqCst), 2);
        observe_send_error(&transmit, &Err(std::io::ErrorKind::WouldBlock.into()));
        assert_eq!(
            OBSERVED.load(Ordering::SeqCst),
            2,
            "backpressure is not a dropped send"
        );
    }
}
