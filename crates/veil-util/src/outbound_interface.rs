//! Outbound interface pinning for Veil's own control-plane sockets.
//!
//! Windows system VPNs install a preferred Wintun default route. Without an
//! explicit interface on the embedded node's TCP/UDP sockets, its local SOCKS
//! upstream is captured by its own packet tunnel and recursively re-enters
//! Veil. Linux solves the same problem with a cgroup fwmark; Windows exposes
//! the per-socket `IP_UNICAST_IF` and `IPV6_UNICAST_IF` options instead.
//!
//! Defaults are captured when `NodeRuntime` starts and refreshed before new
//! sockets are configured. A default through our own Wintun keeps the saved
//! underlay pin, rather than recursively entering Veil. Other platforms compile
//! the socket configuration API as a no-op.

use std::io;
use std::sync::Mutex;

static OUTBOUND_INTERFACES: Mutex<PinnedInterfaces> =
    Mutex::new(PinnedInterfaces { ipv4: 0, ipv6: 0 });

/// Shared with the Windows helper that creates the adapter. An external VPN
/// remains eligible; only our own adapter would feed control traffic back in.
pub const WINDOWS_VPN_ADAPTER_NAME: &str = "xVeil VPN";

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

/// Replace the saved process-wide pin. Zero leaves that family to OS routing.
pub fn set_pinned_interfaces(interfaces: PinnedInterfaces) {
    *crate::lock!(&OUTBOUND_INTERFACES) = interfaces;
}

pub fn pinned_interfaces() -> PinnedInterfaces {
    *crate::lock!(&OUTBOUND_INTERFACES)
}

/// Refresh only the socket's address families, preserving a saved external
/// interface when the current best route enters our own packet tunnel.
#[cfg(windows)]
fn refresh_default_interfaces(families: SocketFamilies) -> io::Result<PinnedInterfaces> {
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
    let mut saved = crate::lock!(&OUTBOUND_INTERFACES);
    let next = resolve_interfaces(&mut saved, families, |family, previous| {
        let destination = match family {
            SocketFamilies::V4 => (&raw const v4_destination).cast::<SOCKADDR>(),
            SocketFamilies::V6 => (&raw const v6_destination).cast::<SOCKADDR>(),
            SocketFamilies::Dual => unreachable!("resolve one family at a time"),
        };
        let route = match best_index(destination) {
            Ok(index) => {
                if !is_own_tunnel(&interface_alias(index)?) {
                    DefaultInterface::Outside(index)
                } else {
                    // Indices can be recycled. The saved index must still name
                    // an existing non-Veil interface, not the new tunnel.
                    let usable = previous != 0
                        && interface_alias(previous).is_ok_and(|alias| !is_own_tunnel(&alias));
                    DefaultInterface::OwnTunnel {
                        saved_usable: usable,
                    }
                }
            }
            Err(code) => {
                use windows_sys::Win32::Foundation::{
                    ERROR_HOST_UNREACHABLE, ERROR_NETWORK_UNREACHABLE, ERROR_NOT_FOUND,
                };
                if matches!(
                    code,
                    ERROR_HOST_UNREACHABLE | ERROR_NETWORK_UNREACHABLE | ERROR_NOT_FOUND
                ) {
                    DefaultInterface::Missing
                } else {
                    return Err(io::Error::from_raw_os_error(code as i32));
                }
            }
        };
        select_pin(previous, route)
    })?;
    Ok(next)
}

/// Capture initial defaults before a tunnel is started. Socket configuration
/// refreshes them again later; no internet default is valid for a LAN-only
/// host, but this initializer reports it to its existing startup caller.
#[cfg(windows)]
pub fn pin_current_default_interfaces() -> io::Result<PinnedInterfaces> {
    let interfaces = refresh_default_interfaces(SocketFamilies::Dual)?;
    if interfaces.ipv4 == 0 && interfaces.ipv6 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NetworkUnreachable,
            "no default interface",
        ));
    }
    Ok(interfaces)
}

#[cfg(windows)]
fn interface_alias(index: u32) -> io::Result<String> {
    use windows_sys::Win32::NetworkManagement::{
        IpHelper::{ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias},
        Ndis::NET_LUID_LH,
    };
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: valid initialized output storage and a synchronous API call.
    let status = unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let mut alias = [0u16; 257];
    // SAFETY: luid came from Windows; the buffer has the documented maximum
    // alias size plus NUL, and Length is measured in UTF-16 characters.
    let status = unsafe { ConvertInterfaceLuidToAlias(&luid, alias.as_mut_ptr(), alias.len()) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let end = alias.iter().position(|c| *c == 0).unwrap_or(alias.len());
    Ok(String::from_utf16_lossy(&alias[..end]))
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug)]
enum DefaultInterface {
    Outside(u32),
    Missing,
    OwnTunnel { saved_usable: bool },
}

#[cfg(any(windows, test))]
fn is_own_tunnel(alias: &str) -> bool {
    alias.eq_ignore_ascii_case(WINDOWS_VPN_ADAPTER_NAME)
}

#[cfg(any(windows, test))]
fn select_pin(previous: u32, route: DefaultInterface) -> io::Result<u32> {
    match route {
        DefaultInterface::Outside(index) if index != 0 => Ok(index),
        DefaultInterface::Missing => Ok(0), // allow OS routing on LAN-only hosts
        DefaultInterface::OwnTunnel { saved_usable: true } if previous != 0 => Ok(previous),
        _ => Err(io::Error::new(
            io::ErrorKind::NetworkUnreachable,
            "no known underlay interface outside Veil's own tunnel",
        )),
    }
}

#[cfg(any(windows, test))]
fn resolve_interfaces(
    saved: &mut PinnedInterfaces,
    families: SocketFamilies,
    mut resolve: impl FnMut(SocketFamilies, u32) -> io::Result<u32>,
) -> io::Result<PinnedInterfaces> {
    let mut previous = *saved;
    if matches!(families, SocketFamilies::V4 | SocketFamilies::Dual) {
        previous.ipv4 = resolve(SocketFamilies::V4, previous.ipv4)?;
    }
    if matches!(families, SocketFamilies::V6 | SocketFamilies::Dual) {
        previous.ipv6 = resolve(SocketFamilies::V6, previous.ipv6)?;
    }
    *saved = previous;
    Ok(previous)
}

#[cfg(not(windows))]
pub fn pin_current_default_interfaces() -> io::Result<PinnedInterfaces> {
    Ok(PinnedInterfaces::default())
}

#[cfg(any(windows, test))]
fn apply_interface_pins(
    pinned: PinnedInterfaces,
    families: SocketFamilies,
    mut apply: impl FnMut(SocketFamilies, u32) -> io::Result<()>,
) -> io::Result<()> {
    if matches!(families, SocketFamilies::V4 | SocketFamilies::Dual) {
        // IP_UNICAST_IF uniquely expects its interface index in network order.
        apply(SocketFamilies::V4, pinned.ipv4.to_be())?;
    }
    if matches!(families, SocketFamilies::V6 | SocketFamilies::Dual) {
        apply(SocketFamilies::V6, pinned.ipv6)?;
    }
    Ok(())
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
        // Zero actively clears a prior pin on a reused socket; skipping the
        // call would preserve the obsolete interface after a route vanished.
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
    let pinned = refresh_default_interfaces(families)?;
    apply_interface_pins(pinned, families, |family, value| match family {
        SocketFamilies::V4 => apply(raw, IPPROTO_IP, IP_UNICAST_IF, value),
        SocketFamilies::V6 => apply(raw, IPPROTO_IPV6, IPV6_UNICAST_IF, value),
        SocketFamilies::Dual => unreachable!("apply one family at a time"),
    })
}

#[cfg(not(windows))]
pub fn configure_outbound_socket<S>(_socket: &S, _families: SocketFamilies) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_PIN_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn pin_round_trips_without_truncating_interface_indices() {
        let _guard = crate::lock!(&TEST_PIN_LOCK);
        let previous = pinned_interfaces();
        let expected = PinnedInterfaces {
            ipv4: 0x00ff_abcd,
            ipv6: 0x7fff_fffe,
        };
        set_pinned_interfaces(expected);
        assert_eq!(pinned_interfaces(), expected);
        set_pinned_interfaces(previous);
    }

    #[test]
    fn fresh_defaults_replace_wifi_ethernet_and_external_vpn_pins() {
        let mut pins = PinnedInterfaces { ipv4: 3, ipv6: 4 };
        for (v4, v6) in [(7, 8), (11, 12), (7, 8)] {
            pins = resolve_interfaces(&mut pins, SocketFamilies::Dual, |family, previous| {
                let next = if family == SocketFamilies::V4 { v4 } else { v6 };
                select_pin(previous, DefaultInterface::Outside(next))
            })
            .unwrap();
            assert_eq!(pins, PinnedInterfaces { ipv4: v4, ipv6: v6 });
        }
    }

    #[test]
    fn own_tunnel_keeps_only_a_still_known_external_pin() {
        assert_eq!(
            select_pin(7, DefaultInterface::OwnTunnel { saved_usable: true }).unwrap(),
            7
        );
        for previous in [0, 7] {
            assert!(
                select_pin(
                    previous,
                    DefaultInterface::OwnTunnel {
                        saved_usable: false
                    }
                )
                .is_err()
            );
        }
        assert!(select_pin(0, DefaultInterface::OwnTunnel { saved_usable: true }).is_err());
    }

    #[test]
    fn missing_default_clears_stale_pin_for_lan_only_routing() {
        assert_eq!(select_pin(7, DefaultInterface::Missing).unwrap(), 0);
        assert!(select_pin(7, DefaultInterface::Outside(0)).is_err());
    }

    #[test]
    fn a_v4_socket_does_not_depend_on_an_unavailable_v6_route() {
        let mut old = PinnedInterfaces { ipv4: 3, ipv6: 4 };
        let mut next = resolve_interfaces(&mut old, SocketFamilies::V4, |family, _| {
            assert_eq!(family, SocketFamilies::V4);
            Ok(7)
        })
        .unwrap();
        assert_eq!(next, PinnedInterfaces { ipv4: 7, ipv6: 4 });
        let next = resolve_interfaces(&mut next, SocketFamilies::V6, |family, _| {
            assert_eq!(family, SocketFamilies::V6);
            Ok(8)
        })
        .unwrap();
        assert_eq!(next, PinnedInterfaces { ipv4: 7, ipv6: 8 });
    }

    #[test]
    fn failed_dual_refresh_does_not_publish_a_half_updated_pair() {
        let mut saved = PinnedInterfaces { ipv4: 3, ipv6: 4 };
        let candidate = resolve_interfaces(&mut saved, SocketFamilies::Dual, |family, _| {
            if family == SocketFamilies::V4 {
                Ok(7)
            } else {
                Err(io::Error::other("interface changed during query"))
            }
        });
        assert!(candidate.is_err());
        assert_eq!(saved, PinnedInterfaces { ipv4: 3, ipv6: 4 });
    }

    #[test]
    fn own_tunnel_detection_does_not_exclude_other_vpns() {
        assert!(is_own_tunnel(WINDOWS_VPN_ADAPTER_NAME));
        assert!(is_own_tunnel("XVEIL VPN"));
        assert!(!is_own_tunnel("External VPN"));
        assert!(!is_own_tunnel("xVeil VPN extra"));
    }

    // Compiled by the Windows --tests check, but not counted as a host test.
    // This is a real Winsock regression check, requiring an actual Windows
    // underlay; fake route-policy fixtures above cannot qualify this OS path.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires Windows with an active external IPv4 default route"]
    fn winsock_socket_replaces_a_stale_interface_index() {
        let _guard = crate::lock!(&TEST_PIN_LOCK);
        struct Restore(PinnedInterfaces);
        impl Drop for Restore {
            fn drop(&mut self) {
                set_pinned_interfaces(self.0);
            }
        }
        let _restore = Restore(pinned_interfaces());
        let current = pin_current_default_interfaces().expect("active external default route");
        assert_ne!(current.ipv4, 0, "test requires an IPv4 underlay");
        let stale = (u32::MAX - 16..=u32::MAX)
            .find(|index| interface_alias(*index).is_err())
            .expect("unused synthetic interface index");
        set_pinned_interfaces(PinnedInterfaces {
            ipv4: stale,
            ipv6: current.ipv6,
        });
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        configure_outbound_socket(&socket, SocketFamilies::V4).expect("refresh before Winsock pin");
        assert_ne!(pinned_interfaces().ipv4, stale);
        assert!(!is_own_tunnel(
            &interface_alias(pinned_interfaces().ipv4).unwrap()
        ));
    }

    #[test]
    fn missing_routes_actually_clear_both_pins_on_reused_sockets() {
        let mut calls = Vec::new();
        apply_interface_pins(
            PinnedInterfaces::default(),
            SocketFamilies::Dual,
            |family, value| {
                calls.push((family, value));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            calls,
            vec![(SocketFamilies::V4, 0), (SocketFamilies::V6, 0)]
        );
    }

    #[test]
    fn socket_pin_values_keep_the_family_specific_byte_order() {
        let pins = PinnedInterfaces {
            ipv4: 0x1234,
            ipv6: 0x5678,
        };
        let mut calls = Vec::new();
        apply_interface_pins(pins, SocketFamilies::Dual, |family, value| {
            calls.push((family, value));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            calls,
            vec![
                (SocketFamilies::V4, 0x1234u32.to_be()),
                (SocketFamilies::V6, 0x5678)
            ]
        );
    }
}
