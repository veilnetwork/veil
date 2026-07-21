use crate::{
    ArgProxy, ProxyType,
    args::ProxySelectorConfig,
    proxy_handler::{ProxyHandler, ProxyHandlerManager},
    session_info::{IpProtocol, SessionInfo},
    socks::SocksProxyManager,
};
use socks5_impl::protocol::Version::V5;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::Mutex,
};

pub(crate) struct RoutingProxyManager {
    fallback: ArgProxy,
    selector: ProxySelectorConfig,
}

impl RoutingProxyManager {
    pub(crate) fn new(fallback: ArgProxy, selector: ProxySelectorConfig) -> Self {
        Self { fallback, selector }
    }

    async fn select(&self, info: SessionInfo) -> std::io::Result<ArgProxy> {
        let selector = async {
            let mut stream = TcpStream::connect(self.selector.addr).await?;
            let protocol = match info.protocol {
                IpProtocol::Tcp => 6,
                IpProtocol::Udp => 17,
                _ => {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "unsupported flow protocol"));
                }
            };
            stream
                .write_all(
                    format!(
                        "{}\t{}\t{}\t{}\t{}\t{}\n",
                        self.selector.token,
                        protocol,
                        info.src.ip(),
                        info.src.port(),
                        info.dst.ip(),
                        info.dst.port(),
                    )
                    .as_bytes(),
                )
                .await?;
            let mut response = String::new();
            let mut reader = BufReader::new(stream).take(129);
            let response_len = reader.read_line(&mut response).await?;
            if response_len == 0 || response_len > 128 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "proxy selector returned an empty or oversized response",
                ));
            }
            let response = response.trim();
            if response == "DEFAULT" {
                return Ok(self.fallback.clone());
            }
            let address: SocketAddr = response
                .parse()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "proxy selector returned an invalid address"))?;
            if !address.ip().is_loopback() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "proxy selector returned a non-loopback address",
                ));
            }
            Ok(ArgProxy {
                proxy_type: ProxyType::Socks5,
                addr: address,
                credentials: None,
            })
        };
        tokio::time::timeout(Duration::from_millis(500), selector)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "proxy selector timed out"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{io::AsyncBufReadExt, net::TcpListener};

    fn flow() -> SessionInfo {
        SessionInfo::new("10.0.0.2:43210".parse().unwrap(), "1.1.1.1:443".parse().unwrap(), IpProtocol::Tcp)
    }

    #[tokio::test]
    async fn authenticated_selector_returns_a_per_flow_loopback_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let selector_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut request = String::new();
            let mut reader = BufReader::new(stream);
            reader.read_line(&mut request).await.unwrap();
            assert_eq!(request, "secret\t6\t10.0.0.2\t43210\t1.1.1.1\t443\n");
            reader.get_mut().write_all(b"127.0.0.1:1091\n").await.unwrap();
        });
        let manager = RoutingProxyManager::new(
            ArgProxy::default(),
            ProxySelectorConfig {
                addr: selector_addr,
                token: "secret".to_owned(),
            },
        );

        let selected = manager.select(flow()).await.unwrap();

        assert_eq!(selected.addr, "127.0.0.1:1091".parse().unwrap());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn selector_rejects_non_loopback_proxy_addresses() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let selector_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"203.0.113.1:1080\n").await.unwrap();
        });
        let manager = RoutingProxyManager::new(
            ArgProxy::default(),
            ProxySelectorConfig {
                addr: selector_addr,
                token: "secret".to_owned(),
            },
        );

        let error = manager.select(flow()).await.unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        server.await.unwrap();
    }
}

#[async_trait::async_trait]
impl ProxyHandlerManager for RoutingProxyManager {
    async fn new_proxy_handler(
        &self,
        info: SessionInfo,
        domain_name: Option<String>,
        udp_associate: bool,
    ) -> std::io::Result<Arc<Mutex<dyn ProxyHandler>>> {
        let selected = self.select(info).await?;
        if selected.proxy_type != ProxyType::Socks5 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "flow selector supports SOCKS5 only",
            ));
        }
        SocksProxyManager::new(selected.addr, V5, selected.credentials)
            .new_proxy_handler(info, domain_name, udp_associate)
            .await
    }
}
