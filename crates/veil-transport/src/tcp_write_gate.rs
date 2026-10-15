//! Local TCP write admission, independent of payloads and session priorities.
//! Darwin's NOTSENT_LOWAT affects readiness but does not bound writes through
//! Tokio's cached writable flag. Recheck the kernel before each small write.

use crate::traits::IoStream;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

pub(crate) struct TcpWriteGate<T> {
    inner: T,
    #[cfg(target_vendor = "apple")]
    socket: for<'a> fn(&'a T) -> &'a TcpStream,
    #[cfg(target_vendor = "apple")]
    writable: Option<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>,
}

pub(crate) fn gate<T: IoStream>(
    inner: T,
    socket: for<'a> fn(&'a T) -> &'a TcpStream,
) -> TcpWriteGate<T> {
    #[cfg(target_vendor = "apple")]
    let writable = {
        use std::os::fd::AsFd;
        let tcp = socket(&inner);
        crate::tcp::clamp_uplink_sndbuf(tcp);
        // A separate readiness registration cannot steal the encrypted
        // reader's write wakeup (TLS reads can themselves flush protocol data).
        // This duplicates a descriptor, never a connection or stream budget.
        tcp.as_fd()
            .try_clone_to_owned()
            .and_then(|fd| {
                tokio::io::unix::AsyncFd::with_interest(fd, tokio::io::Interest::WRITABLE)
            })
            .ok()
    };
    #[cfg(not(target_vendor = "apple"))]
    let _ = socket;
    TcpWriteGate {
        inner,
        #[cfg(target_vendor = "apple")]
        socket,
        #[cfg(target_vendor = "apple")]
        writable,
    }
}

#[cfg(target_vendor = "apple")]
fn poll_permission(
    stream: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    use std::os::fd::AsRawFd;
    loop {
        let mut ready = std::task::ready!(stream.poll_write_ready(cx))?;
        let result = ready.try_io(|stream| {
            loop {
                let mut descriptor = libc::pollfd {
                    fd: stream.get_ref().as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: one initialized pollfd is live, its borrowed socket
                // remains owned, and a zero timeout never blocks this worker.
                let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                if descriptor.revents & libc::POLLNVAL != 0 {
                    return Err(io::Error::from_raw_os_error(libc::EBADF));
                }
                if descriptor.revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) != 0 {
                    return Ok(());
                }
                // Clear only the observed Tokio readiness tick. A new kernel
                // event registers the same task again when unsent data drains.
                return Err(io::ErrorKind::WouldBlock.into());
            }
        });
        match result {
            Err(_) => continue,
            Ok(result) => return Poll::Ready(result),
        }
    }
}

impl<T: IoStream> AsyncRead for TcpWriteGate<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: IoStream> AsyncWrite for TcpWriteGate<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        #[cfg(target_vendor = "apple")]
        let buf = {
            if let Some(writable) = &self.writable {
                std::task::ready!(poll_permission(writable, cx))?;
            }
            // One caller write must not immediately refill the 64-KiB socket
            // buffer after the readiness check. Partial writes preserve all
            // reliable bytes and all framing boundaries at the stream layer.
            &buf[..buf.len().min(4096)]
        };
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        #[cfg(target_vendor = "apple")]
        {
            self.as_mut().poll_write(
                cx,
                bufs.iter().find(|b| !b.is_empty()).map_or(&[], |b| &b[..]),
            )
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
        }
    }

    fn is_write_vectored(&self) -> bool {
        #[cfg(target_vendor = "apple")]
        {
            false
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            self.inner.is_write_vectored()
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush already admitted framing, rather than treating a kernel ACK
        // as flush completion. The next input write must obtain new readiness.
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(target_vendor = "apple")]
impl<T> std::os::fd::AsRawFd for TcpWriteGate<T> {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd((self.socket)(&self.inner))
    }
}
