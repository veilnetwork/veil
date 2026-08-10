#![cfg(target_os = "linux")]

use crate::{SocketDomain, SocketProtocol, error};
use nix::{
    errno::Errno,
    fcntl::{self, FdFlag},
    sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, SockType, cmsg_space, getsockopt, recvmsg, sendmsg, sockopt},
};
use serde::{Deserialize, Serialize};
use std::{
    io::{ErrorKind, IoSlice, IoSliceMut, Result},
    ops::DerefMut,
    os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
};
use tokio::net::{TcpSocket, UdpSocket, UnixDatagram};

const REQUEST_BUFFER_SIZE: usize = 64;

/// Most sockets one [`Request`] may ask the parent to make.
///
/// The requester asks for exactly this many and nothing else ever does, so the
/// ceiling and the request are one number — see `create_socket_queue` in
/// `lib.rs`.
///
/// It is a CEILING because `number` arrives from the namespace child, which is
/// the less privileged side of this socket. `u32::MAX` used to reach a
/// `Vec::with_capacity` in the parent (16 GiB of reservation) and then a loop
/// asking the parent's namespace for four billion sockets. Neither is
/// something the child is entitled to ask for (report9 V-07).
pub const MAX_SOCKETS_PER_REQUEST: u32 = 64;

#[derive(bincode::Encode, bincode::Decode, Hash, Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
struct Request {
    protocol: SocketProtocol,
    domain: SocketDomain,
    number: u32,
}

#[derive(bincode::Encode, bincode::Decode, PartialEq, Debug, Hash, Copy, Clone, Eq, Serialize, Deserialize)]
enum Response {
    Ok,
}

/// Reconstruct socket from raw `fd`
pub fn reconstruct_socket(fd: RawFd) -> Result<OwnedFd> {
    // `fd` is confirmed to be valid so it should be closed
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };

    // Check if `fd` is valid
    let fd_flags = fcntl::fcntl(socket.as_fd(), fcntl::F_GETFD)?;

    // Insert CLOEXEC flag to the `fd` to prevent further propagation across `execve(2)` calls
    let mut fd_flags = FdFlag::from_bits(fd_flags).ok_or(ErrorKind::Unsupported)?;
    if !fd_flags.contains(FdFlag::FD_CLOEXEC) {
        fd_flags.insert(FdFlag::FD_CLOEXEC);
        fcntl::fcntl(socket.as_fd(), fcntl::F_SETFD(fd_flags))?;
    }

    Ok(socket)
}

/// Reconstruct transfer socket from `fd`
///
/// Panics if called outside of tokio runtime
pub fn reconstruct_transfer_socket(fd: OwnedFd) -> Result<UnixDatagram> {
    // Check if socket of type DATAGRAM
    let sock_type = getsockopt(&fd, sockopt::SockType)?;
    if !matches!(sock_type, SockType::Datagram) {
        return Err(ErrorKind::InvalidInput.into());
    }

    let std_socket: std::os::unix::net::UnixDatagram = fd.into();
    std_socket.set_nonblocking(true)?;

    // Fails if tokio context is absent
    Ok(UnixDatagram::from_std(std_socket).unwrap())
}

/// Create pair of interconnected sockets one of which is set to stay open across `execve(2)` calls.
pub async fn create_transfer_socket_pair() -> std::io::Result<(UnixDatagram, OwnedFd)> {
    let (local, remote) = tokio::net::UnixDatagram::pair()?;

    let remote_fd: OwnedFd = remote.into_std().unwrap().into();

    // Get `remote_fd` flags
    let fd_flags = fcntl::fcntl(remote_fd.as_fd(), fcntl::F_GETFD)?;

    // Remove CLOEXEC flag from the `remote_fd` to allow propagating across `execve(2)`
    let mut fd_flags = FdFlag::from_bits(fd_flags).ok_or(ErrorKind::Unsupported)?;
    fd_flags.remove(FdFlag::FD_CLOEXEC);
    fcntl::fcntl(remote_fd.as_fd(), fcntl::F_SETFD(fd_flags))?;

    Ok((local, remote_fd))
}

pub trait TransferableSocket: Sized {
    fn from_fd(fd: OwnedFd) -> Result<Self>;
    fn domain() -> SocketProtocol;
}

impl TransferableSocket for TcpSocket {
    fn from_fd(fd: OwnedFd) -> Result<Self> {
        // Check if socket is of type STREAM
        let sock_type = getsockopt(&fd, sockopt::SockType)?;
        if !matches!(sock_type, SockType::Stream) {
            return Err(ErrorKind::InvalidInput.into());
        }

        let std_stream: std::net::TcpStream = fd.into();
        std_stream.set_nonblocking(true)?;

        Ok(TcpSocket::from_std_stream(std_stream))
    }

    fn domain() -> SocketProtocol {
        SocketProtocol::Tcp
    }
}

impl TransferableSocket for UdpSocket {
    /// Panics if called outside of tokio runtime
    fn from_fd(fd: OwnedFd) -> Result<Self> {
        // Check if socket is of type DATAGRAM
        let sock_type = getsockopt(&fd, sockopt::SockType)?;
        if !matches!(sock_type, SockType::Datagram) {
            return Err(ErrorKind::InvalidInput.into());
        }

        let std_socket: std::net::UdpSocket = fd.into();
        std_socket.set_nonblocking(true)?;

        Ok(UdpSocket::try_from(std_socket).unwrap())
    }

    fn domain() -> SocketProtocol {
        SocketProtocol::Udp
    }
}

/// Send [`Request`] to `socket` and return received [`TransferableSocket`]s
///
/// Panics if called outside of tokio runtime
pub async fn request_sockets<S, T>(mut socket: S, domain: SocketDomain, number: u32) -> error::Result<Vec<T>>
where
    S: DerefMut<Target = UnixDatagram>,
    T: TransferableSocket,
{
    // Borrow socket as mut to prevent multiple simultaneous requests
    let socket = socket.deref_mut();

    // The same ceiling the parent enforces, applied here so the two sides
    // agree by construction. `number` sizes two allocations below, and the
    // parent will not answer with more than this however much is asked.
    let number = number.min(MAX_SOCKETS_PER_REQUEST);

    let mut request = [0u8; 1000];

    // Send request
    let size = bincode::encode_into_slice(
        Request {
            protocol: T::domain(),
            domain,
            number,
        },
        &mut request,
        bincode::config::standard(),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    socket.send(&request[..size]).await?;

    // Receive response
    loop {
        socket.readable().await?;

        let mut buf = [0_u8; REQUEST_BUFFER_SIZE];
        let mut iov = [IoSliceMut::new(&mut buf[..])];
        let mut cmsg = vec![0; cmsg_space::<RawFd>() * number as usize];
        let msg = recvmsg::<()>(socket.as_fd().as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::empty());

        let msg = match msg {
            Err(Errno::EAGAIN) => continue,
            msg => msg?,
        };

        // Parse response
        let response = &msg.iovs().next().unwrap()[..msg.bytes];
        let response: Response = bincode::decode_from_slice(response, bincode::config::standard())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
            .0;
        if !matches!(response, Response::Ok) {
            return Err("Request for new sockets failed".into());
        }

        // Process received file descriptors
        let mut sockets = Vec::<T>::with_capacity(number as usize);
        for cmsg in msg.cmsgs()? {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                for fd in fds {
                    if fd < 0 {
                        return Err("Received socket is invalid".into());
                    }

                    let owned_fd = reconstruct_socket(fd)?;
                    sockets.push(T::from_fd(owned_fd)?);
                }
            }
        }

        return Ok(sockets);
    }
}

/// Process [`Request`]s received from `socket`
///
/// Panics if called outside of tokio runtime
pub async fn process_socket_requests(socket: &UnixDatagram, shutdown_token: tokio_util::sync::CancellationToken) -> error::Result<()> {
    log::info!("socket_transfer: process_socket_requests started");
    loop {
        let mut buf = [0_u8; REQUEST_BUFFER_SIZE];

        let len = tokio::select! {
            _ = shutdown_token.cancelled() => break,
            res = socket.recv(&mut buf[..]) => res?,
        };

        let request: Request = bincode::decode_from_slice(&buf[..len], bincode::config::standard())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
            .0;

        let response = Response::Ok;
        let mut buf = [0u8; 1000];
        let size = bincode::encode_into_slice(response, &mut buf, bincode::config::standard())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        // Clamped rather than refused: a response still goes out, so a child
        // that asked for too much gets what it is entitled to instead of
        // waiting on a reply that never comes — and the parent's socket
        // broker keeps serving every other child.
        let number = request.number.min(MAX_SOCKETS_PER_REQUEST);
        if number != request.number {
            log::warn!(
                "socket_transfer: request for {} sockets clamped to {number} — nothing asks for more",
                request.number
            );
        }

        let mut owned_fd_buf: Vec<OwnedFd> = Vec::with_capacity(number as usize);
        for _ in 0..number {
            let fd = match request.protocol {
                SocketProtocol::Tcp => match request.domain {
                    SocketDomain::IpV4 => tokio::net::TcpSocket::new_v4(),
                    SocketDomain::IpV6 => tokio::net::TcpSocket::new_v6(),
                }
                .map(|s| unsafe { OwnedFd::from_raw_fd(s.into_raw_fd()) }),
                SocketProtocol::Udp => match request.domain {
                    SocketDomain::IpV4 => tokio::net::UdpSocket::bind("0.0.0.0:0").await,
                    SocketDomain::IpV6 => tokio::net::UdpSocket::bind("[::]:0").await,
                }
                .map(|s| s.into_std().unwrap().into()),
            };
            match fd {
                Err(err) => log::warn!("Failed to allocate socket: {err}"),
                Ok(fd) => owned_fd_buf.push(fd),
            };
        }

        socket.writable().await?;

        let raw_fd_buf: Vec<RawFd> = owned_fd_buf.iter().map(|fd| fd.as_raw_fd()).collect();
        let cmsg = ControlMessage::ScmRights(&raw_fd_buf[..]);
        let iov = [IoSlice::new(&buf[..size])];

        sendmsg::<()>(socket.as_raw_fd(), &iov, &[cmsg], MsgFlags::empty(), None)?;
    }
    log::info!("socket_transfer: process_socket_requests exiting");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket as TokioUdpSocket;

    /// The parent must not build whatever the child asks it for.
    ///
    /// `number` crosses this socket from the namespace child, which is the
    /// less privileged side. `u32::MAX` reached a `Vec::with_capacity` in the
    /// parent — sixteen gibibytes of reservation — and then a loop asking the
    /// parent's own namespace for four billion sockets. The child is not
    /// entitled to either, and nothing legitimate asks for more than
    /// `MAX_SOCKETS_PER_REQUEST` (report9 V-07).
    ///
    /// Clamped rather than refused, so the reply still goes out: a child that
    /// overreached gets what it is entitled to instead of blocking on an
    /// answer that never comes, and the broker keeps serving.
    #[tokio::test]
    async fn a_request_past_the_ceiling_is_clamped_not_obeyed() {
        let (parent, child) = UnixDatagram::pair().expect("socketpair");
        let token = tokio_util::sync::CancellationToken::new();
        let server = tokio::spawn({
            let token = token.clone();
            async move {
                let _ = process_socket_requests(&parent, token).await;
            }
        });

        let mut child = child;
        // Asked for through the real client, so the request on the wire is
        // the one the parent actually parses.
        let sockets: Vec<TokioUdpSocket> = request_sockets(&mut child, SocketDomain::IpV4, u32::MAX)
            .await
            .expect("the broker refused to answer at all");

        assert!(
            sockets.len() <= MAX_SOCKETS_PER_REQUEST as usize,
            "the parent handed out {} sockets for one request — the ceiling is {}",
            sockets.len(),
            MAX_SOCKETS_PER_REQUEST
        );
        // And it answered with something, so the clamp did not turn into a
        // silent refusal that would hang the child.
        assert!(!sockets.is_empty(), "the clamp swallowed the request entirely");

        token.cancel();
        let _ = server.await;
    }
}
