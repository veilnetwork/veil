//! Outbound interface pinning for Veil's own control-plane sockets.
//!
//! Windows system VPNs install a preferred Wintun default route. Without an
//! explicit interface on the embedded node's TCP/UDP sockets, its local SOCKS
//! upstream is captured by its own packet tunnel and recursively re-enters
//! Veil. Linux solves the same problem with a cgroup fwmark; Windows exposes
//! the per-socket `IP_UNICAST_IF` and `IPV6_UNICAST_IF` options instead.
//!
//! The physical defaults are pinned when `NodeRuntime` starts, before any VPN
//! route is installed. Socket factories then apply the cached index before
//! connect/send. Other platforms intentionally compile this API as a no-op.

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};

static OUTBOUND_V4_INTERFACE: AtomicU32 = AtomicU32::new(0);
static OUTBOUND_V6_INTERFACE: AtomicU32 = AtomicU32::new(0);

/// Address families a socket can send.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketFamilies {
    V4,
    V6,
    Dual,
}

/// Interface indices pinned for Veil-owned outbound sockets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PinnedInterfaces {
    pub ipv4: u32,
    pub ipv6: u32,
}

/// Replace the process-wide pin. Zero means that family has no usable route.
pub fn set_pinned_interfaces(interfaces: PinnedInterfaces) {
    OUTBOUND_V4_INTERFACE.store(interfaces.ipv4, Ordering::Release);
    OUTBOUND_V6_INTERFACE.store(interfaces.ipv6, Ordering::Release);
}

pub fn pinned_interfaces() -> PinnedInterfaces {
    PinnedInterfaces {
        ipv4: OUTBOUND_V4_INTERFACE.load(Ordering::Acquire),
        ipv6: OUTBOUND_V6_INTERFACE.load(Ordering::Acquire),
    }
}

/// Snapshot the currently preferred physical/default interfaces.
///
/// On Windows this must run before a Wintun default route is installed. A
/// missing family remains zero (IPv6-only and IPv4-only hosts are valid), but
/// failure to find either family is returned so a VPN helper can fail closed.
#[cfg(windows)]
pub fn pin_current_default_interfaces() -> io::Result<PinnedInterfaces> {
    use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterfaceEx;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR, SOCKADDR_IN,
        SOCKADDR_IN6, SOCKADDR_IN6_0,
    };

    fn best_index(destination: *const SOCKADDR) -> Result<u32, u32> {
        let mut index = 0u32;
        // SAFETY: destination points to a correctly-sized sockaddr for the
        // duration of this synchronous call; index is a valid out pointer.
        let status = unsafe { GetBestInterfaceEx(destination, &mut index) };
        if status == 0 && index != 0 {
            Ok(index)
        } else {
            Err(status)
        }
    }

    let v4_destination = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes([1, 1, 1, 1]),
            },
        },
        sin_zero: [0; 8],
    };
    let v6_destination = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: [
                    0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
                ],
            },
        },
        Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
    };
    let v4 = best_index((&raw const v4_destination).cast::<SOCKADDR>());
    let v6 = best_index((&raw const v6_destination).cast::<SOCKADDR>());
    let interfaces = PinnedInterfaces {
        ipv4: v4.unwrap_or(0),
        ipv6: v6.unwrap_or(0),
    };
    if interfaces.ipv4 == 0 && interfaces.ipv6 == 0 {
        let code = v4
            .err()
            .filter(|value| *value != 0)
            .or_else(|| v6.err().filter(|value| *value != 0))
            .unwrap_or(1);
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    set_pinned_interfaces(interfaces);
    Ok(interfaces)
}

#[cfg(not(windows))]
pub fn pin_current_default_interfaces() -> io::Result<PinnedInterfaces> {
    Ok(PinnedInterfaces::default())
}

/// Apply the pinned interface indices before a socket connects or sends.
#[cfg(windows)]
pub fn configure_outbound_socket<S>(socket: &S, families: SocketFamilies) -> io::Result<()>
where
    S: std::os::windows::io::AsRawSocket,
{
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET_ERROR, WSAGetLastError,
        setsockopt,
    };

    fn apply(raw: usize, level: i32, option: i32, value: u32) -> io::Result<()> {
        if value == 0 {
            return Ok(());
        }
        // SAFETY: raw is borrowed from a live socket and the option value is a
        // four-byte DWORD, exactly as required by both Winsock options.
        let result = unsafe {
            setsockopt(
                raw,
                level,
                option,
                (&raw const value).cast::<u8>(),
                std::mem::size_of::<u32>() as i32,
            )
        };
        if result == SOCKET_ERROR {
            // SAFETY: WSAGetLastError has no preconditions and reads the
            // calling thread's last Winsock error.
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        Ok(())
    }

    let raw = socket.as_raw_socket() as usize;
    let pinned = pinned_interfaces();
    if matches!(families, SocketFamilies::V4 | SocketFamilies::Dual) {
        // IP_UNICAST_IF uniquely expects its interface index in network order.
        apply(raw, IPPROTO_IP, IP_UNICAST_IF, pinned.ipv4.to_be())?;
    }
    if matches!(families, SocketFamilies::V6 | SocketFamilies::Dual) {
        apply(raw, IPPROTO_IPV6, IPV6_UNICAST_IF, pinned.ipv6)?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn configure_outbound_socket<S>(_socket: &S, _families: SocketFamilies) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_round_trips_without_truncating_interface_indices() {
        let previous = pinned_interfaces();
        let expected = PinnedInterfaces {
            ipv4: 0x00ff_abcd,
            ipv6: 0x7fff_fffe,
        };
        set_pinned_interfaces(expected);
        assert_eq!(pinned_interfaces(), expected);
        set_pinned_interfaces(previous);
    }
}
