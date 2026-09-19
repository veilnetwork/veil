//! SOCKS5 wire codec — a clean-room implementation from RFC 1928 and RFC 1929.
//!
//! WHY THIS EXISTS AT ALL.
//!
//! tun2proxy previously took these types from `socks5-impl`, which is
//! `GPL-3.0-or-later`. That was compatible while the veil workspace was
//! AGPL-3.0-or-later and stopped being so the moment it became
//! `MIT OR Apache-2.0`: a GPL dependency makes the BINARY that links it GPL,
//! whatever the source license field says. The dependency was reachable from
//! exactly two crates (`veil-vpn-helper` on Windows, `veilclient-ffi` under
//! the `packet-tunnel` feature), and SOCKS5 is how the tunnel talks to veil's
//! own local proxy — so it could not simply be dropped.
//!
//! Written from the specifications, not from the crate it replaces. The
//! protocol is small, frozen since 1996, and the shapes below are named to
//! match the call sites so the swap is an import change rather than a rewrite
//! of seven files.
//!
//! WHAT IS AND IS NOT HERE. Only the client-side codec tun2proxy actually
//! uses: the greeting, username/password authentication, the request/reply
//! pair, and the UDP request header. There is no server, no GSSAPI, and no
//! SOCKS4 encoder — SOCKS4 requests are built byte-by-byte at the call site
//! and only the version number comes from here.
//!
//! Wire formats implemented (all multi-byte integers big-endian):
//!
//! ```text
//! greeting request   VER  NMETHODS  METHODS…                       (RFC 1928 §3)
//! greeting reply     VER  METHOD                                   (RFC 1928 §3)
//! userpass request   0x01 ULEN UNAME PLEN PASSWD                   (RFC 1929 §2)
//! userpass reply     0x01 STATUS                                   (RFC 1929 §2)
//! request            VER  CMD  RSV  ATYP  DST.ADDR  DST.PORT       (RFC 1928 §4)
//! reply              VER  REP  RSV  ATYP  BND.ADDR  BND.PORT       (RFC 1928 §6)
//! udp header         RSV(2)  FRAG  ATYP  DST.ADDR  DST.PORT        (RFC 1928 §7)
//! address            0x01 → 4 bytes | 0x03 → LEN + LEN bytes | 0x04 → 16 bytes
//! ```

use std::io::{Error, ErrorKind, Read, Result, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub use bytes::BufMut;

/// Read and write a protocol element.
///
/// `write_to_buf` is the primitive and the other writers are built on it, so a
/// type cannot serialize one way into a buffer and another way onto a stream.
/// `len` must agree with what `write_to_buf` produces: callers slice incoming
/// datagrams by it (`&buf[header.len()..]`), so a disagreement silently
/// corrupts payloads rather than failing.
pub trait StreamOperation {
    fn retrieve_from_stream<R>(stream: &mut R) -> Result<Self>
    where
        R: Read,
        Self: Sized;

    fn write_to_buf<B: BufMut>(&self, buf: &mut B);

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn write_to_stream<W: Write>(&self, w: &mut W) -> Result<()> {
        let mut buf = Vec::with_capacity(self.len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf)
    }
}

/// The same elements over an async stream.
#[async_trait::async_trait]
pub trait AsyncStreamOperation: StreamOperation {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> Result<Self>
    where
        R: tokio::io::AsyncRead + Unpin + Send + ?Sized,
        Self: Sized;

    async fn write_to_async_stream<W>(&self, w: &mut W) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin + Send + ?Sized,
    {
        use tokio::io::AsyncWriteExt;
        let mut buf = Vec::with_capacity(self.len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }
}

fn invalid(what: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, what)
}

// ── version ──────────────────────────────────────────────────────────────────

/// The protocol version byte. SOCKS4 appears here because tun2proxy speaks
/// both and branches on it; only V5 is encoded by this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Version {
    V4 = 4,
    V5 = 5,
}

impl TryFrom<u8> for Version {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            4 => Ok(Version::V4),
            5 => Ok(Version::V5),
            _ => Err(invalid("unknown SOCKS version")),
        }
    }
}

impl From<Version> for u8 {
    fn from(v: Version) -> u8 {
        v as u8
    }
}

// ── authentication methods ───────────────────────────────────────────────────

/// A method byte from the greeting.
///
/// `Other` is deliberate: the greeting offers methods a server may answer with
/// anything, and a client that panicked or refused on an unknown byte would be
/// less useful than one that reports it and declines. The call site offers
/// two deliberately-unassigned values to fingerprint over-eager proxies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMethod {
    NoAuth,
    GssApi,
    UserPass,
    NoAcceptableMethods,
    Other(u8),
}

impl From<u8> for AuthMethod {
    fn from(b: u8) -> Self {
        match b {
            0x00 => AuthMethod::NoAuth,
            0x01 => AuthMethod::GssApi,
            0x02 => AuthMethod::UserPass,
            0xff => AuthMethod::NoAcceptableMethods,
            other => AuthMethod::Other(other),
        }
    }
}

impl From<AuthMethod> for u8 {
    fn from(m: AuthMethod) -> u8 {
        match m {
            AuthMethod::NoAuth => 0x00,
            AuthMethod::GssApi => 0x01,
            AuthMethod::UserPass => 0x02,
            AuthMethod::NoAcceptableMethods => 0xff,
            AuthMethod::Other(b) => b,
        }
    }
}

/// Username and password for RFC 1929.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UserKey {
    pub username: String,
    pub password: String,
}

impl UserKey {
    pub fn new<U: Into<String>, P: Into<String>>(username: U, password: P) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

/// What gets escaped when these fields go into a proxy URL: EVERYTHING that is
/// not alphanumeric, `-`, `_`, `.` and `~` included.
///
/// Deliberately the same aggressive set the crate this module replaces used,
/// and the reason is worth stating because a gentler set is so tempting: this
/// is a drop-in replacement, and the code around it was written against the
/// old behaviour. `http.rs` in particular tells Basic-auth apart from URL
/// interpolation BY the fact that `Display` mangles `-` and `_` — narrow the
/// set and that distinction silently disappears along with the regression test
/// built on it. A clean-room reimplementation may not quietly change semantics
/// it was not asked to change.
///
/// `percent_decode` on the parsing side is symmetric under either set, so the
/// round trip is unaffected either way; what is affected is every caller that
/// reasoned about the output.
const USERINFO_ESCAPE: &percent_encoding::AsciiSet = percent_encoding::NON_ALPHANUMERIC;

/// `username:password`, percent-encoded for interpolation into a proxy URL.
///
/// The counterpart of the `percent_decode` in `ArgProxy::from_str`: these two
/// have to agree, or a password survives being written out and comes back
/// different. Not for HTTP Basic — RFC 7617 base64-encodes the pair verbatim,
/// and `basic_auth_header_value` does that separately for exactly this reason.
impl std::fmt::Display for UserKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let u = percent_encoding::utf8_percent_encode(&self.username, USERINFO_ESCAPE);
        let p = percent_encoding::utf8_percent_encode(&self.password, USERINFO_ESCAPE);
        write!(f, "{u}:{p}")
    }
}

// ── addresses ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressType {
    IPv4,
    Domain,
    IPv6,
}

impl From<AddressType> for u8 {
    fn from(t: AddressType) -> u8 {
        match t {
            AddressType::IPv4 => 0x01,
            AddressType::Domain => 0x03,
            AddressType::IPv6 => 0x04,
        }
    }
}

/// A SOCKS5 address: a resolved socket address, or a name left for the proxy
/// to resolve.
///
/// The domain form is the reason a tunnel is worth having: forwarding the NAME
/// lets the proxy resolve it, so the client never emits a DNS query of its own.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Address {
    SocketAddress(SocketAddr),
    DomainAddress(String, u16),
}

impl Address {
    pub fn get_type(&self) -> AddressType {
        match self {
            Address::SocketAddress(SocketAddr::V4(_)) => AddressType::IPv4,
            Address::SocketAddress(SocketAddr::V6(_)) => AddressType::IPv6,
            Address::DomainAddress(..) => AddressType::Domain,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Address::SocketAddress(a) => a.port(),
            Address::DomainAddress(_, p) => *p,
        }
    }

    /// The address as a socket address, when it already is one.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Address::SocketAddress(a) => Some(*a),
            Address::DomainAddress(..) => None,
        }
    }

    /// The unspecified IPv4 address, which is what a reply carries when the
    /// server has nothing meaningful to bind-report.
    pub fn unspecified() -> Self {
        Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::SocketAddress(a) => write!(f, "{a}"),
            Address::DomainAddress(d, p) => write!(f, "{d}:{p}"),
        }
    }
}

/// A name is not an address, and the caller has to say what to do about it.
///
/// Refused rather than resolved, and that is the difference from
/// `ToSocketAddrs` below: this conversion performs NO I/O. Forwarding the NAME
/// rather than resolving it is the reason the domain form exists, so a client
/// reaching for a socket address has almost always taken a wrong turn — and a
/// silent DNS lookup here would be the very leak the tunnel is meant to avoid.
impl TryFrom<&Address> for SocketAddr {
    type Error = Error;
    fn try_from(a: &Address) -> Result<Self> {
        a.socket_addr()
            .ok_or_else(|| invalid("SOCKS5 address is a domain name, not a socket address"))
    }
}

impl TryFrom<Address> for SocketAddr {
    type Error = Error;
    fn try_from(a: Address) -> Result<Self> {
        SocketAddr::try_from(&a)
    }
}

/// Resolution, for the one caller that must do it: the UDP gateway SERVER,
/// whose whole job is to reach the named destination. Deliberately a separate,
/// explicitly-called path from `TryFrom` above, which never touches the
/// network — so a client cannot resolve a name by accident.
impl std::net::ToSocketAddrs for Address {
    type Iter = std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> Result<Self::Iter> {
        match self {
            Address::SocketAddress(a) => Ok(vec![*a].into_iter()),
            Address::DomainAddress(d, p) => {
                let resolved: Vec<SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(d.as_str(), *p))?.collect();
                Ok(resolved.into_iter())
            }
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(a: SocketAddr) -> Self {
        Address::SocketAddress(a)
    }
}

impl From<(String, u16)> for Address {
    fn from((d, p): (String, u16)) -> Self {
        Address::DomainAddress(d, p)
    }
}

impl From<(&str, u16)> for Address {
    fn from((d, p): (&str, u16)) -> Self {
        Address::DomainAddress(d.to_owned(), p)
    }
}

impl StreamOperation for Address {
    fn retrieve_from_stream<R>(stream: &mut R) -> Result<Self>
    where
        R: Read,
    {
        let mut atyp = [0u8; 1];
        stream.read_exact(&mut atyp)?;
        match atyp[0] {
            0x01 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets)?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port)?;
                Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(octets),
                    u16::from_be_bytes(port),
                ))))
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len)?;
                // A zero-length name is not a name. Refused here rather than
                // turned into an empty host that every later layer has to
                // second-guess.
                if len[0] == 0 {
                    return Err(invalid("empty SOCKS5 domain name"));
                }
                let mut name = vec![0u8; len[0] as usize];
                stream.read_exact(&mut name)?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port)?;
                let name = String::from_utf8(name).map_err(|_| invalid("SOCKS5 domain is not UTF-8"))?;
                Ok(Address::DomainAddress(name, u16::from_be_bytes(port)))
            }
            0x04 => {
                let mut octets = [0u8; 16];
                stream.read_exact(&mut octets)?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port)?;
                Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(octets),
                    u16::from_be_bytes(port),
                    0,
                    0,
                ))))
            }
            _ => Err(invalid("unknown SOCKS5 address type")),
        }
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match self {
            Address::SocketAddress(SocketAddr::V4(a)) => {
                buf.put_u8(0x01);
                buf.put_slice(&a.ip().octets());
                buf.put_u16(a.port());
            }
            Address::SocketAddress(SocketAddr::V6(a)) => {
                buf.put_u8(0x04);
                buf.put_slice(&a.ip().octets());
                buf.put_u16(a.port());
            }
            Address::DomainAddress(d, p) => {
                // TRUNCATED, NOT PANICKING. The length field is one byte, so a
                // longer name cannot be expressed; a hostname that long is
                // already invalid per RFC 1035 and refusing to encode it here
                // would abort a tunnel over a malformed request.
                let bytes = d.as_bytes();
                let n = bytes.len().min(u8::MAX as usize);
                buf.put_u8(0x03);
                buf.put_u8(n as u8);
                buf.put_slice(&bytes[..n]);
                buf.put_u16(*p);
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Address::SocketAddress(SocketAddr::V4(_)) => 1 + 4 + 2,
            Address::SocketAddress(SocketAddr::V6(_)) => 1 + 16 + 2,
            Address::DomainAddress(d, _) => 1 + 1 + d.len().min(u8::MAX as usize) + 2,
        }
    }
}

#[async_trait::async_trait]
impl AsyncStreamOperation for Address {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> Result<Self>
    where
        R: tokio::io::AsyncRead + Unpin + Send + ?Sized,
    {
        use tokio::io::AsyncReadExt;
        let atyp = r.read_u8().await?;
        match atyp {
            0x01 => {
                let mut octets = [0u8; 4];
                r.read_exact(&mut octets).await?;
                let port = r.read_u16().await?;
                Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(octets),
                    port,
                ))))
            }
            0x03 => {
                let len = r.read_u8().await?;
                if len == 0 {
                    return Err(invalid("empty SOCKS5 domain name"));
                }
                let mut name = vec![0u8; len as usize];
                r.read_exact(&mut name).await?;
                let port = r.read_u16().await?;
                let name = String::from_utf8(name).map_err(|_| invalid("SOCKS5 domain is not UTF-8"))?;
                Ok(Address::DomainAddress(name, port))
            }
            0x04 => {
                let mut octets = [0u8; 16];
                r.read_exact(&mut octets).await?;
                let port = r.read_u16().await?;
                Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(octets),
                    port,
                    0,
                    0,
                ))))
            }
            _ => Err(invalid("unknown SOCKS5 address type")),
        }
    }
}

// ── commands and replies ─────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl From<Command> for u8 {
    fn from(c: Command) -> u8 {
        c as u8
    }
}

impl TryFrom<u8> for Command {
    type Error = Error;
    fn try_from(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Command::Connect),
            0x02 => Ok(Command::Bind),
            0x03 => Ok(Command::UdpAssociate),
            _ => Err(invalid("unknown SOCKS5 command")),
        }
    }
}

/// RFC 1928 §6 reply codes. `Other` keeps an unassigned code readable in a log
/// instead of collapsing every unknown failure into one name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reply {
    Succeeded,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    Other(u8),
}

impl From<u8> for Reply {
    fn from(b: u8) -> Self {
        match b {
            0x00 => Reply::Succeeded,
            0x01 => Reply::GeneralFailure,
            0x02 => Reply::ConnectionNotAllowed,
            0x03 => Reply::NetworkUnreachable,
            0x04 => Reply::HostUnreachable,
            0x05 => Reply::ConnectionRefused,
            0x06 => Reply::TtlExpired,
            0x07 => Reply::CommandNotSupported,
            0x08 => Reply::AddressTypeNotSupported,
            other => Reply::Other(other),
        }
    }
}

impl From<Reply> for u8 {
    fn from(r: Reply) -> u8 {
        match r {
            Reply::Succeeded => 0x00,
            Reply::GeneralFailure => 0x01,
            Reply::ConnectionNotAllowed => 0x02,
            Reply::NetworkUnreachable => 0x03,
            Reply::HostUnreachable => 0x04,
            Reply::ConnectionRefused => 0x05,
            Reply::TtlExpired => 0x06,
            Reply::CommandNotSupported => 0x07,
            Reply::AddressTypeNotSupported => 0x08,
            Reply::Other(b) => b,
        }
    }
}

impl std::fmt::Display for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Reply::Succeeded => "succeeded",
            Reply::GeneralFailure => "general SOCKS server failure",
            Reply::ConnectionNotAllowed => "connection not allowed by ruleset",
            Reply::NetworkUnreachable => "network unreachable",
            Reply::HostUnreachable => "host unreachable",
            Reply::ConnectionRefused => "connection refused",
            Reply::TtlExpired => "TTL expired",
            Reply::CommandNotSupported => "command not supported",
            Reply::AddressTypeNotSupported => "address type not supported",
            Reply::Other(b) => return write!(f, "unassigned reply code {b:#04x}"),
        };
        f.write_str(s)
    }
}

/// RFC 1928 §4 — the client's request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub command: Command,
    pub address: Address,
}

impl Request {
    pub fn new(command: Command, address: Address) -> Self {
        Self { command, address }
    }
}

impl StreamOperation for Request {
    fn retrieve_from_stream<R>(stream: &mut R) -> Result<Self>
    where
        R: Read,
    {
        let mut head = [0u8; 3];
        stream.read_exact(&mut head)?;
        if Version::try_from(head[0])? != Version::V5 {
            return Err(invalid("SOCKS5 request with a non-5 version"));
        }
        let command = Command::try_from(head[1])?;
        let address = Address::retrieve_from_stream(stream)?;
        Ok(Self { command, address })
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(Version::V5.into());
        buf.put_u8(self.command.into());
        buf.put_u8(0x00); // RSV
        self.address.write_to_buf(buf);
    }

    fn len(&self) -> usize {
        3 + self.address.len()
    }
}

/// RFC 1928 §6 — the server's reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub reply: Reply,
    pub address: Address,
}

impl Response {
    pub fn new(reply: Reply, address: Address) -> Self {
        Self { reply, address }
    }
}

impl StreamOperation for Response {
    fn retrieve_from_stream<R>(stream: &mut R) -> Result<Self>
    where
        R: Read,
    {
        let mut head = [0u8; 3];
        stream.read_exact(&mut head)?;
        if Version::try_from(head[0])? != Version::V5 {
            return Err(invalid("SOCKS5 reply with a non-5 version"));
        }
        let reply = Reply::from(head[1]);
        let address = Address::retrieve_from_stream(stream)?;
        Ok(Self { reply, address })
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(Version::V5.into());
        buf.put_u8(self.reply.into());
        buf.put_u8(0x00); // RSV
        self.address.write_to_buf(buf);
    }

    fn len(&self) -> usize {
        3 + self.address.len()
    }
}

/// RFC 1928 §7 — the header in front of every relayed datagram.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpHeader {
    pub frag: u8,
    pub address: Address,
}

impl UdpHeader {
    pub fn new(frag: u8, address: Address) -> Self {
        Self { frag, address }
    }
}

impl StreamOperation for UdpHeader {
    fn retrieve_from_stream<R>(stream: &mut R) -> Result<Self>
    where
        R: Read,
    {
        let mut head = [0u8; 3];
        stream.read_exact(&mut head)?;
        // head[0..2] is RSV and must be zero; a non-zero value means this is
        // not a SOCKS5 datagram and the payload offset would be guessed.
        if head[0] != 0 || head[1] != 0 {
            return Err(invalid("SOCKS5 UDP header with non-zero RSV"));
        }
        let address = Address::retrieve_from_stream(stream)?;
        Ok(Self { frag: head[2], address })
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16(0x0000); // RSV
        buf.put_u8(self.frag);
        self.address.write_to_buf(buf);
    }

    fn len(&self) -> usize {
        3 + self.address.len()
    }
}

#[async_trait::async_trait]
impl AsyncStreamOperation for UdpHeader {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> Result<Self>
    where
        R: tokio::io::AsyncRead + Unpin + Send + ?Sized,
    {
        use tokio::io::AsyncReadExt;
        let rsv = r.read_u16().await?;
        if rsv != 0 {
            return Err(invalid("SOCKS5 UDP header with non-zero RSV"));
        }
        let frag = r.read_u8().await?;
        let address = Address::retrieve_from_async_stream(r).await?;
        Ok(Self { frag, address })
    }
}

// ── greeting (RFC 1928 §3) ───────────────────────────────────────────────────

pub mod handshake {
    use super::*;

    /// The client's method list.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Request {
        pub methods: Vec<AuthMethod>,
    }

    impl Request {
        pub fn new(methods: Vec<AuthMethod>) -> Self {
            Self { methods }
        }
    }

    impl StreamOperation for Request {
        fn retrieve_from_stream<R>(stream: &mut R) -> Result<Self>
        where
            R: Read,
        {
            let mut head = [0u8; 2];
            stream.read_exact(&mut head)?;
            if Version::try_from(head[0])? != Version::V5 {
                return Err(invalid("SOCKS5 greeting with a non-5 version"));
            }
            let mut methods = vec![0u8; head[1] as usize];
            stream.read_exact(&mut methods)?;
            Ok(Self {
                methods: methods.into_iter().map(AuthMethod::from).collect(),
            })
        }

        fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
            // Same one-byte ceiling as the domain length, and the same reason
            // to clamp rather than abort: the count field cannot express more.
            let n = self.methods.len().min(u8::MAX as usize);
            buf.put_u8(Version::V5.into());
            buf.put_u8(n as u8);
            for m in &self.methods[..n] {
                buf.put_u8((*m).into());
            }
        }

        fn len(&self) -> usize {
            2 + self.methods.len().min(u8::MAX as usize)
        }
    }

    /// The method the server picked.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Response {
        pub method: AuthMethod,
    }

    impl Response {
        pub fn new(method: AuthMethod) -> Self {
            Self { method }
        }
    }

    impl StreamOperation for Response {
        fn retrieve_from_stream<R>(stream: &mut R) -> Result<Self>
        where
            R: Read,
        {
            let mut head = [0u8; 2];
            stream.read_exact(&mut head)?;
            if Version::try_from(head[0])? != Version::V5 {
                return Err(invalid("SOCKS5 greeting reply with a non-5 version"));
            }
            Ok(Self {
                method: AuthMethod::from(head[1]),
            })
        }

        fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
            buf.put_u8(Version::V5.into());
            buf.put_u8(self.method.into());
        }

        fn len(&self) -> usize {
            2
        }
    }
}

// ── username/password authentication (RFC 1929) ──────────────────────────────

pub mod password_method {
    use super::*;

    /// The sub-negotiation version, which is 1 and is NOT the SOCKS version.
    /// Mixing the two is the classic way to make this exchange fail against a
    /// strict server, so it is named rather than written as a bare literal.
    pub const SUBNEGOTIATION_VERSION: u8 = 0x01;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Status {
        Succeeded,
        Failed(u8),
    }

    impl From<u8> for Status {
        fn from(b: u8) -> Self {
            if b == 0 { Status::Succeeded } else { Status::Failed(b) }
        }
    }

    impl From<Status> for u8 {
        fn from(s: Status) -> u8 {
            match s {
                Status::Succeeded => 0,
                Status::Failed(b) => b,
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Request {
        pub user_key: UserKey,
    }

    impl Request {
        pub fn new<U: AsRef<str>, P: AsRef<str>>(username: U, password: P) -> Self {
            Self {
                user_key: UserKey::new(username.as_ref(), password.as_ref()),
            }
        }
    }

    impl StreamOperation for Request {
        fn retrieve_from_stream<R>(stream: &mut R) -> Result<Self>
        where
            R: Read,
        {
            let mut ver = [0u8; 1];
            stream.read_exact(&mut ver)?;
            if ver[0] != SUBNEGOTIATION_VERSION {
                return Err(invalid("username/password auth with a non-1 version"));
            }
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut username = vec![0u8; len[0] as usize];
            stream.read_exact(&mut username)?;
            stream.read_exact(&mut len)?;
            let mut password = vec![0u8; len[0] as usize];
            stream.read_exact(&mut password)?;
            let username = String::from_utf8(username).map_err(|_| invalid("username is not UTF-8"))?;
            let password = String::from_utf8(password).map_err(|_| invalid("password is not UTF-8"))?;
            Ok(Self {
                user_key: UserKey::new(username, password),
            })
        }

        fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
            let u = self.user_key.username.as_bytes();
            let p = self.user_key.password.as_bytes();
            let un = u.len().min(u8::MAX as usize);
            let pn = p.len().min(u8::MAX as usize);
            buf.put_u8(SUBNEGOTIATION_VERSION);
            buf.put_u8(un as u8);
            buf.put_slice(&u[..un]);
            buf.put_u8(pn as u8);
            buf.put_slice(&p[..pn]);
        }

        fn len(&self) -> usize {
            3 + self.user_key.username.len().min(u8::MAX as usize) + self.user_key.password.len().min(u8::MAX as usize)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Response {
        pub status: Status,
    }

    impl Response {
        pub fn new(status: Status) -> Self {
            Self { status }
        }
    }

    impl StreamOperation for Response {
        fn retrieve_from_stream<R>(stream: &mut R) -> Result<Self>
        where
            R: Read,
        {
            let mut head = [0u8; 2];
            stream.read_exact(&mut head)?;
            if head[0] != SUBNEGOTIATION_VERSION {
                return Err(invalid("username/password reply with a non-1 version"));
            }
            Ok(Self {
                status: Status::from(head[1]),
            })
        }

        fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
            buf.put_u8(SUBNEGOTIATION_VERSION);
            buf.put_u8(self.status.into());
        }

        fn len(&self) -> usize {
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `len` is what callers slice payloads by, so it has to equal what the
    /// encoder actually emits — for every address shape, not the one the test
    /// author happened to pick.
    #[test]
    fn len_agrees_with_the_bytes_written() {
        let cases = [
            Address::SocketAddress("1.2.3.4:80".parse().unwrap()),
            Address::SocketAddress("[2001:db8::1]:443".parse().unwrap()),
            Address::DomainAddress("example.com".to_owned(), 8080),
        ];
        for a in cases {
            let mut buf = Vec::new();
            a.write_to_buf(&mut buf);
            assert_eq!(buf.len(), a.len(), "{a} encodes {} bytes", buf.len());
            let header = UdpHeader::new(0, a.clone());
            let mut hbuf = Vec::new();
            header.write_to_buf(&mut hbuf);
            assert_eq!(hbuf.len(), header.len(), "udp header for {a}");
        }
    }

    #[test]
    fn addresses_round_trip() {
        for a in [
            Address::SocketAddress("1.2.3.4:80".parse().unwrap()),
            Address::SocketAddress("[2001:db8::1]:443".parse().unwrap()),
            Address::DomainAddress("example.com".to_owned(), 8080),
        ] {
            let mut buf = Vec::new();
            a.write_to_buf(&mut buf);
            let back = Address::retrieve_from_stream(&mut &buf[..]).expect("decode");
            assert_eq!(a, back);
        }
    }

    /// The bytes on the wire, not merely self-consistency: a codec that agrees
    /// only with itself passes a round-trip and still cannot talk to a proxy.
    /// Vectors read off RFC 1928 §4 and §7 by hand.
    #[test]
    fn request_matches_the_rfc_layout() {
        let req = Request::new(Command::Connect, Address::SocketAddress("127.0.0.1:1080".parse().unwrap()));
        let mut buf = Vec::new();
        req.write_to_buf(&mut buf);
        assert_eq!(
            buf,
            vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38],
            "VER CMD RSV ATYP ADDR PORT",
        );
    }

    #[test]
    fn domain_request_matches_the_rfc_layout() {
        let req = Request::new(Command::UdpAssociate, Address::from(("ab".to_owned(), 1)));
        let mut buf = Vec::new();
        req.write_to_buf(&mut buf);
        assert_eq!(
            buf,
            vec![0x05, 0x03, 0x00, 0x03, 0x02, b'a', b'b', 0x00, 0x01],
            "VER CMD RSV ATYP LEN NAME PORT",
        );
    }

    #[test]
    fn udp_header_matches_the_rfc_layout() {
        let h = UdpHeader::new(0, Address::SocketAddress("1.2.3.4:53".parse().unwrap()));
        let mut buf = Vec::new();
        h.write_to_buf(&mut buf);
        assert_eq!(
            buf,
            vec![0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x35],
            "RSV RSV FRAG ATYP ADDR PORT",
        );
    }

    /// RFC 1929's version byte is 1. Writing the SOCKS version there is the
    /// classic way to be rejected by a strict server.
    #[test]
    fn userpass_uses_the_subnegotiation_version_not_five() {
        let req = password_method::Request::new("u", "pw");
        let mut buf = Vec::new();
        req.write_to_buf(&mut buf);
        assert_eq!(buf, vec![0x01, 0x01, b'u', 0x02, b'p', b'w']);
        assert_eq!(buf.len(), req.len());
    }

    #[test]
    fn greeting_round_trips_and_keeps_unassigned_methods() {
        let req = handshake::Request::new(vec![AuthMethod::NoAuth, AuthMethod::from(4_u8), AuthMethod::UserPass]);
        let mut buf = Vec::new();
        req.write_to_buf(&mut buf);
        assert_eq!(buf, vec![0x05, 0x03, 0x00, 0x04, 0x02]);
        let back = handshake::Request::retrieve_from_stream(&mut &buf[..]).expect("decode");
        assert_eq!(back.methods[1], AuthMethod::Other(4));
    }

    #[test]
    fn a_reply_reports_its_code() {
        let bytes = vec![0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let resp = Response::retrieve_from_stream(&mut &bytes[..]).expect("decode");
        assert_eq!(resp.reply, Reply::ConnectionRefused);
    }

    /// A datagram whose RSV is not zero is not a SOCKS5 datagram. Accepting it
    /// would take `len()` bytes off the front of someone else's payload.
    #[test]
    fn a_udp_header_with_dirty_rsv_is_refused() {
        let bytes = vec![0x00, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x35];
        assert!(UdpHeader::retrieve_from_stream(&mut &bytes[..]).is_err());
    }

    #[test]
    fn an_empty_domain_is_refused() {
        let bytes = [0x03, 0x00, 0x00, 0x50];
        assert!(Address::retrieve_from_stream(&mut &bytes[..]).is_err());
    }

    #[test]
    fn a_truncated_address_is_an_error_not_a_panic() {
        let bytes = [0x01, 1, 2];
        assert!(Address::retrieve_from_stream(&mut &bytes[..]).is_err());
    }

    /// Display and the parser in `ArgProxy::from_str` are one contract: what
    /// this writes, `percent_decode` must give back unchanged.
    #[test]
    fn credentials_round_trip_through_percent_encoding() {
        for (u, pw) in [("user", "pass"), ("session-id_1.2~x", "p@ss:word/with?chars"), ("имя", "пароль")] {
            let key = UserKey::new(u, pw);
            let rendered = key.to_string();
            let (enc_u, enc_p) = rendered.split_once(':').expect("userinfo has a colon");
            use percent_encoding::percent_decode;
            assert_eq!(percent_decode(enc_u.as_bytes()).decode_utf8().unwrap(), u);
            assert_eq!(percent_decode(enc_p.as_bytes()).decode_utf8().unwrap(), pw);
        }
    }

    /// Everything non-alphanumeric is escaped — `-`, `_`, `.` and `~`
    /// INCLUDED, though RFC 3986 calls them unreserved.
    ///
    /// Pinned because the gentler set is the obvious "improvement" and it is
    /// wrong here: `http.rs` distinguishes HTTP Basic auth from URL
    /// interpolation by the fact that this rendering mangles `-` and `_`, and
    /// its regression test asserts the two differ. Leaving those characters
    /// alone makes that assertion vacuous for ordinary credentials — which is
    /// exactly how it was caught (2026-09-20), by a test in ANOTHER module
    /// failing after this one was written to a nicer-looking contract.
    #[test]
    fn every_non_alphanumeric_byte_is_escaped() {
        assert_eq!(UserKey::new("a-b_c.d~e", "x").to_string(), "a%2Db%5Fc%2Ed%7Ee:x",);
    }

    /// The delimiters must NOT survive verbatim, or the URL reparses wrongly.
    #[test]
    fn userinfo_delimiters_are_escaped() {
        let rendered = UserKey::new("a:b", "c@d").to_string();
        assert_eq!(rendered, "a%3Ab:c%40d");
        assert_eq!(rendered.matches(':').count(), 1, "one delimiter only");
    }
}
