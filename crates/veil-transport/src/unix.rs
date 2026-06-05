#![cfg(unix)]

use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::net::{UnixListener, UnixStream};

use super::{
    TransportContext,
    error::{Result, TransportError},
    tcp::{boxed_stream_connection, peer_meta},
    traits::{Transport, TransportCapabilities, TransportConnection, TransportListener},
    uri::TransportUri,
};

/// Unix-domain-socket `Transport` implementation — local-host only.
#[derive(Debug, Default)]
pub struct UnixTransport;

struct UnixTransportListener {
    listener: UnixListener,
    bind_uri: TransportUri,
}

fn unix_path<'a>(uri: &'a TransportUri, action: &str) -> Result<&'a std::path::Path> {
    match uri {
        TransportUri::Unix { path } => Ok(path.as_path()),
        _ => Err(TransportError::Unsupported(format!(
            "unix transport cannot {action} `{}`",
            uri.scheme()
        ))),
    }
}

fn boxed_unix_listener(
    listener: UnixListener,
    bind_uri: TransportUri,
) -> Box<dyn TransportListener> {
    Box::new(UnixTransportListener { listener, bind_uri }) as Box<dyn TransportListener>
}

impl TransportListener for UnixTransportListener {
    fn accept<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let (stream, _) = self.listener.accept().await?;
            let peer = peer_meta("unix", self.bind_uri.clone(), None, None);
            Ok(boxed_stream_connection(peer, stream))
        })
    }

    fn local_addr(&self) -> String {
        self.bind_uri.to_string()
    }
}

impl Transport for UnixTransport {
    fn scheme(&self) -> &'static str {
        "unix"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities::stream_listener()
    }

    fn connect<'a>(
        &'a self,
        uri: &'a TransportUri,
        _ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let path = unix_path(uri, "handle")?;
            let stream = UnixStream::connect(path).await?;
            let peer = peer_meta("unix", uri.clone(), None, None);
            Ok(boxed_stream_connection(peer, stream))
        })
    }

    fn bind<'a>(
        &'a self,
        uri: &'a TransportUri,
        _ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportListener>>> {
        Box::pin(async move {
            let path = unix_path(uri, "bind")?;
            // Attempt unlink-then-bind unconditionally; ignore NotFound so we
            // don't require a prior `exists` check (that check would race
            // with another process creating/removing the path between the
            // two syscalls — TOCTOU). `remove_file` on Unix does not follow
            // symlinks, so a malicious symlink at `path` only removes the
            // symlink itself, not the target.
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            let listener = UnixListener::bind(path)?;
            Ok(boxed_unix_listener(listener, uri.clone()))
        })
    }
}
