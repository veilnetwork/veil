//! Local App IPC payload structs for the OVL1 binary protocol.
//!
//! These payloads are exchanged over the local Unix-domain socket between
//! an application process and the veil node. They belong to
//! `FrameFamily::LocalApp` (family = 6).
//!
//! | Struct | `LocalAppMsg` variant | Direction |
//! |------------------------|-----------------------|----------------|
//! | `AppIpcHelloPayload` | `AppHello` | client → node |
//! | `AppIpcHelloOkPayload` | `AppHelloOk` | node → client |
//! | `AppIpcHelloErrPayload`| `AppHelloErr` | node → client |

use super::ProtoError;

/// Current IPC protocol version spoken by this build. // STABLE v1
pub const IPC_PROTOCOL_VERSION: u16 = 1;

/// Oldest client version this node accepts (inclusive). // STABLE v1
///
/// Clients whose `AppIpcHelloPayload::version` is below this value are
/// rejected with `ipc_hello_err::VERSION_MISMATCH`.
pub const CLIENT_MIN_VERSION: u16 = 1;

/// Newest client version this node accepts (inclusive). // STABLE v1
///
/// Clients whose `AppIpcHelloPayload::version` is above this value are
/// rejected with `ipc_hello_err::VERSION_MISMATCH`.
pub const CLIENT_MAX_VERSION: u16 = 1;

// ── AppIpcHelloPayload ──────────────────────────────────────────────────────

/// Sent by the IPC client immediately after connecting. // STABLE v1
///
/// Wire layout:
/// ```text
/// [0..2] version u16 BE — IPC protocol version the client supports
/// [2..6] flags u32 BE — capability flags (reserved, must be 0)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIpcHelloPayload {
    /// IPC protocol version the client supports.
    pub version: u16,
    /// Capability flags (reserved; must be 0).
    pub flags: u32,
}

impl AppIpcHelloPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 2 + 4;

    /// Encode to the fixed 6-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..2].copy_from_slice(&self.version.to_be_bytes());
        buf[2..6].copy_from_slice(&self.flags.to_be_bytes());
        buf
    }

    /// Parse from a 6-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            version: super::read_u16_be(buf, 0)?,
            flags: super::read_u32_be(buf, 2)?,
        })
    }
}

// ── AppIpcHelloOkPayload ────────────────────────────────────────────────────

/// Sent by the node in response to a valid `APP_HELLO`. // STABLE v1
///
/// Wire layout:
/// ```text
/// [0..2] version u16 BE — negotiated protocol version
/// [2..18] client_token [u8; 16] — random token identifying this IPC session
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIpcHelloOkPayload {
    /// Negotiated protocol version (always equal to `IPC_PROTOCOL_VERSION` today).
    pub version: u16,
    /// Random token identifying this IPC session for subsequent frames.
    pub client_token: [u8; 16],
}

impl AppIpcHelloOkPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 2 + 16;

    /// Encode to the fixed 18-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..2].copy_from_slice(&self.version.to_be_bytes());
        buf[2..18].copy_from_slice(&self.client_token);
        buf
    }

    /// Parse from an 18-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            version: super::read_u16_be(buf, 0)?,
            client_token: super::read_array::<16>(buf, 2)?,
        })
    }
}

// ── AppIpcHelloErrPayload ─────────────────────────────────────────────────── // STABLE v1

/// Error codes for `APP_HELLO_ERR`.
/// Error-code constants carried in `AppIpcHelloErrPayload::error_code`.
pub mod ipc_hello_err {
    /// Client requested an unsupported protocol version.
    pub const VERSION_MISMATCH: u16 = 1;
    /// Node is shutting down and not accepting new IPC clients.
    pub const SHUTTING_DOWN: u16 = 2;
}

/// Sent by the node when the `APP_HELLO` cannot be accepted.
///
/// Wire layout:
/// ```text
/// [0..2] error_code u16 BE
/// [2..4] detail_len u16 BE
/// [4..4+detail_len] detail UTF-8 string (optional human-readable reason)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIpcHelloErrPayload {
    /// Code [`ipc_hello_err`].
    pub error_code: u16,
    /// Optional human-readable detail (UTF-8).
    pub detail: Vec<u8>,
}

impl AppIpcHelloErrPayload {
    const FIXED_SIZE: usize = 2 + 2;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.detail.len() <= u16::MAX as usize, "detail too long");
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + self.detail.len());
        buf.extend_from_slice(&self.error_code.to_be_bytes());
        buf.extend_from_slice(&(self.detail.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.detail);
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let error_code = super::read_u16_be(buf, 0)?;
        let detail_len = super::read_u16_be(buf, 2)? as usize;
        let total = Self::FIXED_SIZE + detail_len;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            error_code,
            detail: buf[4..4 + detail_len].to_vec(),
        })
    }
}

// ── AppBindPayload ───────────────────────────────────────────────────────── // STABLE v1

/// Maximum byte length for the `namespace` field [`AppBindPayload`].
/// Prevents a malicious IPC client from allocating large strings on bind.
pub const MAX_BIND_NS_LEN: usize = 255;

/// Maximum byte length for the `name` field [`AppBindPayload`].
pub const MAX_BIND_NAME_LEN: usize = 255;

/// Sent by the IPC client to register an application endpoint.
///
/// Wire layout:
/// ```text
/// [0..4] endpoint_id u32 BE
/// [4..6] flags u16 BE
/// [6..8] ns_len u16 BE — byte length of namespace (≤ MAX_BIND_NS_LEN)
/// [8..8+ns_len] namespace bytes
/// [8+ns_len..10+ns_len] name_len u16 BE — byte length of name (≤ MAX_BIND_NAME_LEN)
/// [10+ns_len..] name bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppBindPayload {
    /// Endpoint id being registered.
    pub endpoint_id: u32,
    /// Bind flags (see [`ipc_bind_flags`]).
    pub flags: u16,
    /// UTF-8 namespace (≤ `MAX_BIND_NS_LEN`).
    pub namespace: Vec<u8>,
    /// UTF-8 endpoint name (≤ `MAX_BIND_NAME_LEN`).
    pub name: Vec<u8>,
}

impl AppBindPayload {
    /// Encode to wire bytes.
    ///
    /// # Panics
    /// Panics in debug builds if `namespace` or `name` exceed their respective
    /// wire-length limits (`MAX_BIND_NS_LEN` / `MAX_BIND_NAME_LEN`). In
    /// production code only locally-constructed payloads are encoded, so this
    /// is a programmer-error guard, not an input-validation path.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.namespace.len() <= MAX_BIND_NS_LEN,
            "namespace too long: {} > {MAX_BIND_NS_LEN}",
            self.namespace.len()
        );
        debug_assert!(
            self.name.len() <= MAX_BIND_NAME_LEN,
            "name too long: {} > {MAX_BIND_NAME_LEN}",
            self.name.len()
        );
        let ns_len = (self.namespace.len() as u16).to_be_bytes();
        let name_len = (self.name.len() as u16).to_be_bytes();
        let mut buf = Vec::with_capacity(4 + 2 + 2 + self.namespace.len() + 2 + self.name.len());
        buf.extend_from_slice(&self.endpoint_id.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&ns_len);
        buf.extend_from_slice(&self.namespace);
        buf.extend_from_slice(&name_len);
        buf.extend_from_slice(&self.name);
        buf
    }

    /// Parse a bind payload, enforcing `ns_len` and `name_len` caps.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let min = 4 + 2 + 2; // endpoint_id + flags + ns_len
        if buf.len() < min {
            return Err(ProtoError::BufferTooShort {
                need: min,
                got: buf.len(),
            });
        }
        let endpoint_id = super::read_u32_be(buf, 0)?;
        let flags = super::read_u16_be(buf, 4)?;
        let ns_len = super::read_u16_be(buf, 6)? as usize;
        if ns_len > MAX_BIND_NS_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "ns_len",
                value: ns_len as u64,
                max: MAX_BIND_NS_LEN as u64,
            });
        }
        let ns_end = 8 + ns_len;
        if buf.len() < ns_end + 2 {
            return Err(ProtoError::BufferTooShort {
                need: ns_end + 2,
                got: buf.len(),
            });
        }
        let namespace = buf[8..ns_end].to_vec();
        let name_len = super::read_u16_be(buf, ns_end)? as usize;
        if name_len > MAX_BIND_NAME_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "name_len",
                value: name_len as u64,
                max: MAX_BIND_NAME_LEN as u64,
            });
        }
        let name_end = ns_end + 2 + name_len;
        if buf.len() < name_end {
            return Err(ProtoError::BufferTooShort {
                need: name_end,
                got: buf.len(),
            });
        }
        let name = buf[ns_end + 2..name_end].to_vec();
        Ok(Self {
            endpoint_id,
            flags,
            namespace,
            name,
        })
    }
}

// ── AppBindOkPayload ──────────────────────────────────────────────────────── // STABLE v1

/// Sent by the node confirming a successful `APP_BIND`.
///
/// Wire layout:
/// ```text
/// [0..32] app_id [u8; 32]
/// [32..36] endpoint_id u32 BE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppBindOkPayload {
    /// Assigned app_id for the newly-bound endpoint.
    pub app_id: [u8; 32],
    /// Endpoint id echoed from the bind request.
    pub endpoint_id: u32,
}

impl AppBindOkPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 4;

    /// Encode to the fixed 36-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.app_id);
        buf[32..36].copy_from_slice(&self.endpoint_id.to_be_bytes());
        buf
    }

    /// Parse from a 36-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            app_id: super::read_array::<32>(buf, 0)?,
            endpoint_id: super::read_u32_be(buf, 32)?,
        })
    }
}

// ── AppBindErrPayload ─────────────────────────────────────────────────────── // STABLE v1

/// Error codes for `APP_BIND_ERR`.
pub mod ipc_bind_err {
    /// Another client already holds this endpoint.
    pub const ALREADY_BOUND: u16 = 1;
    /// Request was malformed (e.g., empty namespace/name).
    pub const INVALID_REQUEST: u16 = 2;
    /// Per-connection endpoint cap reached.
    pub const RESOURCE_LIMIT: u16 = 3;
}

/// Flags [`AppBindPayload::flags`].
pub mod ipc_bind_flags {
    /// Ephemeral binding: the node mixes the per-connection `client_token` into
    /// the `app_id` derivation — `BLAKE3(node_id || client_token || namespace || name)`.
    ///
    /// Two processes that bind the same `(namespace, name, endpoint_id)` with this
    /// flag will each receive a **distinct** `app_id` in `APP_BIND_OK`, so they can
    /// coexist on the same node without coordination. The derived address is only
    /// valid for the lifetime of the IPC connection; reconnecting produces a new
    /// `client_token` and therefore a new `app_id`.
    ///
    /// Use named mode (`flags = 0`) for well-known services that need a stable address.
    pub const EPHEMERAL: u16 = 0x0001;
}

/// Sent by the node when an `APP_BIND` cannot be honoured.
///
/// Wire layout:
/// ```text
/// [0..2] error_code u16 BE
/// [2..4] detail_len u16 BE
/// [4..] detail UTF-8 string
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppBindErrPayload {
    /// Code [`ipc_bind_err`].
    pub error_code: u16,
    /// Optional human-readable detail (UTF-8).
    pub detail: Vec<u8>,
}

impl AppBindErrPayload {
    const FIXED_SIZE: usize = 4;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.detail.len() <= u16::MAX as usize, "detail too long");
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + self.detail.len());
        buf.extend_from_slice(&self.error_code.to_be_bytes());
        buf.extend_from_slice(&(self.detail.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.detail);
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let error_code = super::read_u16_be(buf, 0)?;
        let detail_len = super::read_u16_be(buf, 2)? as usize;
        let total = Self::FIXED_SIZE + detail_len;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            error_code,
            detail: buf[4..total].to_vec(),
        })
    }
}

// ── AppUnbindPayload ──────────────────────────────────────────────────────── // STABLE v1

/// Sent by the IPC client to deregister an endpoint.
///
/// Wire layout:
/// ```text
/// [0..32] app_id [u8; 32]
/// [32..36] endpoint_id u32 BE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppUnbindPayload {
    /// App id of the endpoint being dropped.
    pub app_id: [u8; 32],
    /// Endpoint id being dropped.
    pub endpoint_id: u32,
}

impl AppUnbindPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 4;

    /// Encode to the fixed 36-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.app_id);
        buf[32..36].copy_from_slice(&self.endpoint_id.to_be_bytes());
        buf
    }

    /// Parse from a 36-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            app_id: super::read_array::<32>(buf, 0)?,
            endpoint_id: super::read_u32_be(buf, 32)?,
        })
    }
}

// ── AppDeliverPayload ─────────────────────────────────────────────────────── // STABLE v1

/// Sent by the node to deliver an incoming veil datagram to the IPC client.
///
/// Wire layout:
/// ```text
/// [0..32] src_node_id [u8; 32]
/// [32..64] src_app_id [u8; 32]
/// [64..96] app_id [u8; 32] (destination, this endpoint's app_id)
/// [96..100] endpoint_id u32 BE (destination endpoint)
/// [100..104] data_len u32 BE
/// [104..104+data_len] data bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppDeliverPayload {
    /// Originator's `node_id`.
    pub src_node_id: [u8; 32],
    /// App-id of the sender on the originating node.
    pub src_app_id: [u8; 32],
    /// Destination app's `app_id` (this client's endpoint).
    pub app_id: [u8; 32],
    /// Destination endpoint id.
    pub endpoint_id: u32,
    /// Delivered datagram bytes. d: pool-backed for symmetry
    /// with AppSendPayload / AppIpcSendPayload — daemon → chat-node hot path.
    pub data: veil_bufpool::PooledShared,
    /// Reply handle (reply-channel): non-zero when this was an authenticated
    /// anonymous message carrying a one-time reply path. The daemon stores the
    /// reply block and surfaces this id; the app replies via it. `0` = no reply
    /// path (plain / meta-E2E / one-way auth deliveries). Appended LAST on the
    /// wire so existing field offsets are unchanged.
    pub reply_id: u64,
}

impl AppDeliverPayload {
    const FIXED_SIZE: usize = 32 + 32 + 32 + 4 + 4;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let data: &[u8] = &self.data;
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + data.len());
        buf.extend_from_slice(&self.src_node_id);
        buf.extend_from_slice(&self.src_app_id);
        buf.extend_from_slice(&self.app_id);
        buf.extend_from_slice(&self.endpoint_id.to_be_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
        // reply_id appended LAST (trailing u64) so header/data offsets are
        // unchanged for the plain path.
        buf.extend_from_slice(&self.reply_id.to_be_bytes());
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let src_node_id = super::read_array::<32>(buf, 0)?;
        let src_app_id = super::read_array::<32>(buf, 32)?;
        let app_id = super::read_array::<32>(buf, 64)?;
        let endpoint_id = super::read_u32_be(buf, 96)?;
        let data_len = super::read_u32_be(buf, 100)? as usize;
        // checked_add — 32-bit overflow defence.
        // total = header + data; the trailing reply_id (u64) follows.
        let total = Self::FIXED_SIZE
            .checked_add(data_len)
            .ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
        let end = total.checked_add(8).ok_or(ProtoError::BufferTooShort {
            need: usize::MAX,
            got: buf.len(),
        })?;
        if buf.len() < end {
            return Err(ProtoError::BufferTooShort {
                need: end,
                got: buf.len(),
            });
        }
        let mut pooled = veil_bufpool::global().acquire(data_len);
        pooled.as_vec_mut().extend_from_slice(&buf[104..total]);
        let reply_id = super::read_u64_be(buf, total)?;
        Ok(Self {
            src_node_id,
            src_app_id,
            app_id,
            endpoint_id,
            data: pooled.into_shared(),
            reply_id,
        })
    }
}

// ── AuthAppDeliver ──────────────────────────────────────────────────────────

/// Domain-separation prefix for the signed bytes of an [`AuthAppDeliver`].
/// Binding it prevents a signature made for some other veil structure from
/// being replayed as an authenticated delivery, and vice-versa.
pub const AUTH_APP_DELIVER_DOMAIN: &[u8] = b"veil-auth-onion-deliver:v1\0";

/// Authenticated anonymous delivery payload (Epic: authenticated onion delivery
/// v1). Carried as the onion FINAL-hop payload under `final_hop_kind::
/// APP_DELIVER_AUTH`. The onion hides the sender's network location from every
/// relay; this payload lets the RECIPIENT cryptographically verify WHO sent it
/// (unlike the anonymous-to-recipient [`AppDeliverPayload`] whose `src_node_id`
/// is unauthenticated / zeroed).
///
/// The recipient verifies: freshness (`timestamp`), the `signature` against
/// `sender_node_id`'s identity subkey `sig_key_idx` (resolved/cached), and
/// per-sender replay on `nonce`. Only then is `sender_node_id` trusted.
///
/// `dst_node_id` (the intended recipient) is **signed but NOT transmitted** —
/// it is part of [`Self::signing_bytes`] so re-targeting is prevented, but the
/// verifier reconstructs it as its OWN node_id ([`Self::signing_bytes_with_dst`]).
/// A relay that re-targets the envelope to a different recipient makes that
/// recipient compute different signing bytes → `BadSignature`. This keeps 32 B
/// off the wire (it matters most for the fragmented rendezvous path).
///
/// Wire layout (big-endian):
/// ```text
/// [0]        version u8 (= 1)
/// [1..33]    sender_node_id [32]
/// [33..35]   sig_key_idx u16 BE   index into the sender's IdentityDocument subkeys
/// [35..43]   timestamp u64 BE     unix secs (freshness)
/// [43..51]   nonce u64 BE         fresh-random per message (replay)
/// [51..83]   app_id [32]          destination app
/// [83..87]   endpoint_id u32 BE
/// [87..91]   data_len u32 BE
/// [91..91+data_len] data
/// [..]       has_reply u8         (1 = a ReplyBlock follows, 0 = none)
/// [..]       reply_block          (ReplyBlock::WIRE_SIZE B, only if has_reply)
/// [..+2]     sig_len u16 BE
/// [..]       signature            (Ed25519 = 64 B in v1)
/// ```
/// (`dst_node_id` is NOT on the wire — see above. The reply block, when
/// present, is BEFORE the signature so the signature covers it.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthAppDeliver {
    /// Format version (1).
    pub version: u8,
    /// Sovereign `node_id` of the sender — VERIFIED by the recipient via
    /// `signature`, NOT trusted until then.
    pub sender_node_id: [u8; 32],
    /// Index of the signing subkey in the sender's IdentityDocument.
    pub sig_key_idx: u16,
    /// Unix-seconds timestamp; recipient enforces a freshness window.
    pub timestamp: u64,
    /// Fresh random per-message nonce; recipient keeps a per-sender replay window.
    pub nonce: u64,
    /// Intended recipient `node_id` — bound into the signed bytes so a relay
    /// cannot re-target the envelope to a different recipient. NOT transmitted
    /// on the wire; the verifier reconstructs it as its own node_id (see
    /// [`Self::signing_bytes_with_dst`]). `decode` leaves this zeroed.
    pub dst_node_id: [u8; 32],
    /// Destination app id.
    pub app_id: [u8; 32],
    /// Destination endpoint id.
    pub endpoint_id: u32,
    /// Application payload.
    pub data: Vec<u8>,
    /// Optional one-time reply path (Mixminion-style reply block). When present
    /// the recipient can reply WITHOUT the sender publishing a public
    /// `RendezvousAd` — the sender embeds a sealed reply path here and registers
    /// R-locally with the named rendezvous relay. Signed (part of
    /// [`Self::signing_bytes`]) so a relay cannot forge/alter it. `None` =
    /// one-way (no reply).
    pub reply_block: Option<ReplyBlock>,
    /// Signature over [`Self::signing_bytes`] by the sender's subkey.
    pub signature: Vec<u8>,
}

/// One-time reply path embedded in an [`AuthAppDeliver`]. Lets the recipient
/// route an authenticated reply back to the sender via the sender's chosen
/// rendezvous relay, with NO public DHT footprint for the sender (presence-leak
/// mitigation). The recipient seals the reply to `x25519_pk`, wraps it as an
/// `IntroducePayload` with `auth_cookie`, and onion-routes it to
/// `rendezvous_node_id`; the relay forwards by cookie to the sender's session.
///
/// Wire layout (fixed `WIRE_SIZE`, big-endian):
/// ```text
/// [0..32]   rendezvous_node_id [32]
/// [32..48]  auth_cookie [16]
/// [48..80]  x25519_pk [32]        sender's anonymity key (seal target)
/// [80..112] reply_app_id [32]     sender's app that receives the reply
/// [112..116] reply_endpoint_id u32 BE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyBlock {
    /// Rendezvous relay that forwards the reply to the original sender.
    pub rendezvous_node_id: [u8; 32],
    /// One-time cookie the sender registered with the relay.
    pub auth_cookie: [u8; 16],
    /// Sender's anonymity X25519 pubkey — the recipient seals the reply to it.
    pub x25519_pk: [u8; 32],
    /// Sender's app that receives the reply.
    pub reply_app_id: [u8; 32],
    /// Endpoint on `reply_app_id` that receives the reply.
    pub reply_endpoint_id: u32,
    /// Sender's LOCAL (transport) node_id — the id it registered with at the
    /// rendezvous relay, and thus the `receiver_node_id` the replier must put in
    /// the reply introduce for the relay's `(receiver_node_id, cookie)` lookup
    /// to hit. NOTE: this is the transport identity, distinct from the SOVEREIGN
    /// `sender_node_id` the recipient verifies — the relay keys registrations by
    /// transport id, so the reply must address that one.
    pub receiver_node_id: [u8; 32],
}

impl ReplyBlock {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 16 + 32 + 32 + 4 + 32;

    fn write_into(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(&self.rendezvous_node_id);
        b.extend_from_slice(&self.auth_cookie);
        b.extend_from_slice(&self.x25519_pk);
        b.extend_from_slice(&self.reply_app_id);
        b.extend_from_slice(&self.reply_endpoint_id.to_be_bytes());
        b.extend_from_slice(&self.receiver_node_id);
    }

    /// Encode to its fixed-size wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::WIRE_SIZE);
        self.write_into(&mut b);
        b
    }

    /// Decode from exactly `WIRE_SIZE` bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            rendezvous_node_id: super::read_array::<32>(buf, 0)?,
            auth_cookie: super::read_array::<16>(buf, 32)?,
            x25519_pk: super::read_array::<32>(buf, 48)?,
            reply_app_id: super::read_array::<32>(buf, 80)?,
            reply_endpoint_id: super::read_u32_be(buf, 112)?,
            receiver_node_id: super::read_array::<32>(buf, 116)?,
        })
    }
}

impl AuthAppDeliver {
    /// Current wire version.
    pub const VERSION: u8 = 1;
    /// Fixed header size before `data` (version..data_len inclusive).
    /// `dst_node_id` is signed but not on the wire, so it is NOT counted here.
    const HEADER_SIZE: usize = 1 + 32 + 2 + 8 + 8 + 32 + 4 + 4;
    /// Cap on the signature length accepted on decode (Falcon-512 ≈ 690 B; v1
    /// uses Ed25519 = 64 B, but the cap leaves room for the hybrid v2 subkey).
    pub const MAX_SIG_LEN: usize = 1024;

    /// Canonical bytes the sender signs, computed with an EXPLICIT `dst` so the
    /// recipient (who reconstructs `dst` as its own node_id) and the sender
    /// (who knows the intended target) derive the same bytes iff the message
    /// was actually for that recipient. Covers every field EXCEPT the signature,
    /// domain-separated. `dst` is bound here but is NOT on the wire.
    pub fn signing_bytes_with_dst(&self, dst: &[u8; 32]) -> Vec<u8> {
        let mut b = Vec::with_capacity(
            AUTH_APP_DELIVER_DOMAIN.len() + Self::HEADER_SIZE + 32 + self.data.len(),
        );
        b.extend_from_slice(AUTH_APP_DELIVER_DOMAIN);
        b.push(self.version);
        b.extend_from_slice(&self.sender_node_id);
        b.extend_from_slice(&self.sig_key_idx.to_be_bytes());
        b.extend_from_slice(&self.timestamp.to_be_bytes());
        b.extend_from_slice(&self.nonce.to_be_bytes());
        b.extend_from_slice(dst);
        b.extend_from_slice(&self.app_id);
        b.extend_from_slice(&self.endpoint_id.to_be_bytes());
        b.extend_from_slice(&self.data);
        // Optional reply block — a presence byte then its bytes (so the
        // signature binds both whether a reply path exists AND its contents).
        match &self.reply_block {
            Some(rb) => {
                b.push(1);
                rb.write_into(&mut b);
            }
            None => b.push(0),
        }
        b
    }

    /// Sender-side signing bytes — binds the intended recipient from
    /// `self.dst_node_id`. The recipient instead calls
    /// [`Self::signing_bytes_with_dst`] with its own node_id.
    pub fn signing_bytes(&self) -> Vec<u8> {
        self.signing_bytes_with_dst(&self.dst_node_id)
    }

    /// Encode to wire bytes (header || data || sig_len || signature).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(Self::HEADER_SIZE + self.data.len() + 2 + self.signature.len());
        buf.push(self.version);
        buf.extend_from_slice(&self.sender_node_id);
        buf.extend_from_slice(&self.sig_key_idx.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.nonce.to_be_bytes());
        // dst_node_id is signed but NOT transmitted (reconstructed as self).
        buf.extend_from_slice(&self.app_id);
        buf.extend_from_slice(&self.endpoint_id.to_be_bytes());
        buf.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.data);
        // Optional reply block (presence byte + bytes) — between data and the
        // signature, matching `signing_bytes` so the sig covers it.
        match &self.reply_block {
            Some(rb) => {
                buf.push(1);
                rb.write_into(&mut buf);
            }
            None => buf.push(0),
        }
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Parse from wire bytes. Does NOT verify the signature — the caller MUST
    /// chain signature + freshness + replay checks (see the recipient flow).
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let version = buf[0];
        if version != Self::VERSION {
            return Err(ProtoError::Malformed(format!(
                "AuthAppDeliver: unsupported version {version}"
            )));
        }
        let sender_node_id = super::read_array::<32>(buf, 1)?;
        let sig_key_idx = u16::from_be_bytes([buf[33], buf[34]]);
        let timestamp = super::read_u64_be(buf, 35)?;
        let nonce = super::read_u64_be(buf, 43)?;
        // dst_node_id is NOT on the wire — left zeroed; the verifier supplies
        // its own node_id via `signing_bytes_with_dst`.
        let app_id = super::read_array::<32>(buf, 51)?;
        let endpoint_id = super::read_u32_be(buf, 83)?;
        let data_len = super::read_u32_be(buf, 87)? as usize;
        let data_end =
            Self::HEADER_SIZE
                .checked_add(data_len)
                .ok_or(ProtoError::BufferTooShort {
                    need: usize::MAX,
                    got: buf.len(),
                })?;
        // Optional reply block: a presence byte at `data_end`, then (if 1) a
        // fixed `ReplyBlock::WIRE_SIZE` section, before the signature.
        if buf.len() <= data_end {
            return Err(ProtoError::BufferTooShort {
                need: data_end + 1,
                got: buf.len(),
            });
        }
        let (reply_block, reply_end) = match buf[data_end] {
            0 => (None, data_end + 1),
            1 => {
                let rb_start = data_end + 1;
                let rb_end = rb_start.checked_add(ReplyBlock::WIRE_SIZE).ok_or(
                    ProtoError::BufferTooShort {
                        need: usize::MAX,
                        got: buf.len(),
                    },
                )?;
                if buf.len() < rb_end {
                    return Err(ProtoError::BufferTooShort {
                        need: rb_end,
                        got: buf.len(),
                    });
                }
                (Some(ReplyBlock::decode(&buf[rb_start..rb_end])?), rb_end)
            }
            other => {
                return Err(ProtoError::Malformed(format!(
                    "AuthAppDeliver: invalid reply-presence byte {other}"
                )));
            }
        };
        // sig_len (u16) follows the (optional) reply block.
        let sig_len_end = reply_end.checked_add(2).ok_or(ProtoError::BufferTooShort {
            need: usize::MAX,
            got: buf.len(),
        })?;
        if buf.len() < sig_len_end {
            return Err(ProtoError::BufferTooShort {
                need: sig_len_end,
                got: buf.len(),
            });
        }
        let sig_len = u16::from_be_bytes([buf[reply_end], buf[reply_end + 1]]) as usize;
        if sig_len > Self::MAX_SIG_LEN {
            return Err(ProtoError::Malformed(format!(
                "AuthAppDeliver: signature {sig_len} B exceeds cap {}",
                Self::MAX_SIG_LEN
            )));
        }
        let total = sig_len_end
            .checked_add(sig_len)
            .ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            version,
            sender_node_id,
            sig_key_idx,
            timestamp,
            nonce,
            // Reconstructed by the verifier via `signing_bytes_with_dst`.
            dst_node_id: [0u8; 32],
            app_id,
            endpoint_id,
            data: buf[Self::HEADER_SIZE..data_end].to_vec(),
            reply_block,
            signature: buf[sig_len_end..total].to_vec(),
        })
    }
}

// ── AuthDeliverFragment ──────────────────────────────────────────────────────

/// Max fragments a single authenticated rendezvous message may be split into.
/// Bounds the receiver's per-message reassembly buffer count.
pub const MAX_AUTH_DELIVER_FRAGMENTS: u16 = 64;

/// Max reassembled `AuthAppDeliver` wire size (across all fragments). Bounds
/// receiver memory per message; the sender enforces the matching application
/// payload ceiling before signing. ~6 KiB ≈ 64 fragments of useful chunk.
pub const MAX_AUTH_DELIVER_MSG_BYTES: usize = 6144;

/// One fragment of a signed [`AuthAppDeliver`], for the rendezvous path where a
/// single onion cell cannot carry the whole signed message (sign-whole-then-
/// fragment). The sender splits `AuthAppDeliver::encode()` into chunks; each
/// fragment is independently sealed + onion-routed to the rendezvous. The
/// receiver reassembles by `msg_id` and verifies the whole message ONCE — the
/// single signature integrity-protects the reassembly (tamper / truncation /
/// reorder → BadSignature).
///
/// Carried as the SEALED introduce plaintext under `final_hop_kind::
/// APP_DELIVER_AUTH` (the 1-byte tag precedes this struct). A small message is
/// simply `frag_count == 1`.
///
/// Wire layout (big-endian):
/// ```text
/// [0..16]   msg_id [16]       random; ties a message's fragments together
/// [16..18]  frag_count u16    total fragments (1..=MAX_AUTH_DELIVER_FRAGMENTS)
/// [18..20]  frag_idx u16      0-based, < frag_count
/// [20..]    chunk             slice of AuthAppDeliver::encode()
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDeliverFragment {
    /// Random per-message id grouping a message's fragments.
    pub msg_id: [u8; 16],
    /// Total number of fragments in this message.
    pub frag_count: u16,
    /// 0-based index of this fragment.
    pub frag_idx: u16,
    /// This fragment's slice of the signed `AuthAppDeliver` bytes.
    pub chunk: Vec<u8>,
}

impl AuthDeliverFragment {
    /// Fixed header before `chunk`.
    pub const HEADER_SIZE: usize = 16 + 2 + 2;

    /// Encode to wire bytes (header || chunk).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.chunk.len());
        buf.extend_from_slice(&self.msg_id);
        buf.extend_from_slice(&self.frag_count.to_be_bytes());
        buf.extend_from_slice(&self.frag_idx.to_be_bytes());
        buf.extend_from_slice(&self.chunk);
        buf
    }

    /// Parse from wire bytes. Validates `frag_count` is in range and
    /// `frag_idx < frag_count`, and that a non-empty chunk is present.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() <= Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::HEADER_SIZE + 1,
                got: buf.len(),
            });
        }
        let msg_id = super::read_array::<16>(buf, 0)?;
        let frag_count = u16::from_be_bytes([buf[16], buf[17]]);
        let frag_idx = u16::from_be_bytes([buf[18], buf[19]]);
        if frag_count == 0 || frag_count > MAX_AUTH_DELIVER_FRAGMENTS {
            return Err(ProtoError::Malformed(format!(
                "AuthDeliverFragment: frag_count {frag_count} out of range (1..={MAX_AUTH_DELIVER_FRAGMENTS})"
            )));
        }
        if frag_idx >= frag_count {
            return Err(ProtoError::Malformed(format!(
                "AuthDeliverFragment: frag_idx {frag_idx} >= frag_count {frag_count}"
            )));
        }
        Ok(Self {
            msg_id,
            frag_count,
            frag_idx,
            chunk: buf[Self::HEADER_SIZE..].to_vec(),
        })
    }
}

// ── AppIpcSendPayload ─────────────────────────────────────────────────────── // STABLE v1

/// Flag bit for `AppIpcSendPayload.flags`: request end-to-end delivery ACK.
pub const IPC_SEND_FLAG_REQUIRE_ACK: u32 = 0x0000_0001;

/// Flag bit for `AppIpcSendPayload.flags`: send anonymously using meta-E2E
/// (onion) encryption.
///
/// When set, the node encrypts `sender_node_id | src_app_id | app_id |
/// endpoint_id | data` under the recipient's ML-KEM public key and sets the
/// outer `DeliveryEnvelope.sender_node_id` to `[0u8; 32]`. Relay nodes see
/// only the destination; the sender identity is revealed only to the recipient
/// after decryption.
///
/// Requires the recipient's ML-KEM encapsulation key to be cached. If the key
/// is not available the server returns `ipc_send_err::NO_E2E_KEY`.
pub const IPC_SEND_FLAG_ANONYMOUS: u32 = 0x0000_0002;

/// Flag bit for `AppIpcSendPayload.flags`: send as an AUTHENTICATED anonymous
/// message over the onion/rendezvous transport. Unlike `ANONYMOUS` (meta-E2E),
/// the recipient cryptographically verifies WHO sent it while no relay learns
/// the sender's location. Mutually exclusive with `ANONYMOUS` (both set →
/// `ipc_send_err::INVALID_FLAGS`). `REQUIRE_ACK` is ignored (fire-and-forget,
/// no end-to-end ACK). Requires the recipient to have opted in to receiving
/// (a resolvable RendezvousAd) and the sender to have a sovereign identity.
pub const IPC_SEND_FLAG_ANONYMOUS_AUTHENTICATED: u32 = 0x0000_0004;

/// Flag bit for `AppIpcSendPayload.flags`: on an authenticated anonymous send,
/// attach a one-time reply block so the recipient can reply WITHOUT either side
/// publishing a public rendezvous ad (no presence leak). The reply will be
/// delivered to `(src_app_id, reply_endpoint_id)` on this node. Only meaningful
/// together with `ANONYMOUS_AUTHENTICATED`; ignored otherwise.
pub const IPC_SEND_FLAG_EXPECT_REPLY: u32 = 0x0000_0008;

/// Flag bit for `AppIpcSendPayload.flags`: this send IS a reply, routed via the
/// opaque `reply_id` the app received alongside an earlier authenticated
/// message (not via `dst_node_id`/`app_id`/`endpoint_id`, which are ignored).
/// The daemon takes the one-time reply block by id and sends back over the
/// original sender's rendezvous path. Mutually exclusive with the explicit
/// destination flags.
pub const IPC_SEND_FLAG_IS_REPLY: u32 = 0x0000_0010;

/// Sent by the IPC client to dispatch a datagram into the veil network.
///
/// Wire layout:
/// ```text
/// [0..32] dst_node_id [u8; 32]
/// [32..64] src_app_id [u8; 32] (sender's own app_id)
/// [64..96] app_id [u8; 32] (destination app_id)
/// [96..100] endpoint_id u32 BE (destination endpoint)
/// [100..104] flags u32 BE (bit 0 = REQUIRE_ACK, bit 1 = ANONYMOUS,
///                           bit 2 = ANONYMOUS_AUTHENTICATED,
///                           bit 3 = EXPECT_REPLY, bit 4 = IS_REPLY)
/// [104..108] data_len u32 BE
/// [108..108+data_len] data bytes
/// [D..D+8]   reply_id u64 BE     (trailing; optional — 0 if absent)
/// [D+8..D+12] reply_endpoint_id u32 BE (trailing; optional — 0 if absent)
/// ```
/// The two trailing fields are appended after `data` so the fixed header offsets
/// stay stable; a pre-reply-channel client (which sends neither) round-trips as
/// `reply_id = 0`, `reply_endpoint_id = 0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIpcSendPayload {
    /// Destination `node_id`.
    pub dst_node_id: [u8; 32],
    /// Sender's own app_id (the bound handle on this node).
    pub src_app_id: [u8; 32],
    /// Destination `app_id`.
    pub app_id: [u8; 32],
    /// Destination endpoint id.
    pub endpoint_id: u32,
    /// Request an end-to-end delivery acknowledgement.
    /// Set `IPC_SEND_FLAG_REQUIRE_ACK` to enable.
    pub require_ack: bool,
    /// Send anonymously using meta-E2E (onion) encryption.
    /// Set `IPC_SEND_FLAG_ANONYMOUS` to enable.
    pub anonymous: bool,
    /// Send as an AUTHENTICATED anonymous message (onion/rendezvous; recipient
    /// verifies the sender). Set `IPC_SEND_FLAG_ANONYMOUS_AUTHENTICATED`.
    /// Mutually exclusive with `anonymous`.
    pub anonymous_authenticated: bool,
    /// On an authenticated send, attach a one-time reply block addressed to
    /// `(src_app_id, reply_endpoint_id)`. Set `IPC_SEND_FLAG_EXPECT_REPLY`.
    pub expect_reply: bool,
    /// This send is a reply routed via `reply_id` (ignores the explicit
    /// destination). Set `IPC_SEND_FLAG_IS_REPLY`.
    pub is_reply: bool,
    /// Opaque reply handle, used when `is_reply`. 0 means "no reply".
    pub reply_id: u64,
    /// Endpoint the eventual reply should be delivered to, used when
    /// `expect_reply` (paired with `src_app_id`).
    pub reply_endpoint_id: u32,
    /// Datagram payload. d: backed by the global bufpool so chat_node-
    /// style 200 msg/sec × 60 KB IPC inbound load doesn't malloc-churn this
    /// allocator-side. Clone is cheap (Arc-style refcount).
    pub data: veil_bufpool::PooledShared,
}

impl AppIpcSendPayload {
    const FIXED_SIZE: usize = 32 + 32 + 32 + 4 + 4 + 4; // 108

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let data_slice: &[u8] = &self.data;
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + data_slice.len());
        buf.extend_from_slice(&self.dst_node_id);
        buf.extend_from_slice(&self.src_app_id);
        buf.extend_from_slice(&self.app_id);
        buf.extend_from_slice(&self.endpoint_id.to_be_bytes());
        let mut flags: u32 = 0;
        if self.require_ack {
            flags |= IPC_SEND_FLAG_REQUIRE_ACK;
        }
        if self.anonymous {
            flags |= IPC_SEND_FLAG_ANONYMOUS;
        }
        if self.anonymous_authenticated {
            flags |= IPC_SEND_FLAG_ANONYMOUS_AUTHENTICATED;
        }
        if self.expect_reply {
            flags |= IPC_SEND_FLAG_EXPECT_REPLY;
        }
        if self.is_reply {
            flags |= IPC_SEND_FLAG_IS_REPLY;
        }
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&(data_slice.len() as u32).to_be_bytes());
        buf.extend_from_slice(data_slice);
        // Trailing reply fields (after data — keeps fixed offsets stable).
        buf.extend_from_slice(&self.reply_id.to_be_bytes());
        buf.extend_from_slice(&self.reply_endpoint_id.to_be_bytes());
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let dst_node_id = super::read_array::<32>(buf, 0)?;
        let src_app_id = super::read_array::<32>(buf, 32)?;
        let app_id = super::read_array::<32>(buf, 64)?;
        let endpoint_id = super::read_u32_be(buf, 96)?;
        let flags = super::read_u32_be(buf, 100)?;
        let require_ack = flags & IPC_SEND_FLAG_REQUIRE_ACK != 0;
        let anonymous = flags & IPC_SEND_FLAG_ANONYMOUS != 0;
        let anonymous_authenticated = flags & IPC_SEND_FLAG_ANONYMOUS_AUTHENTICATED != 0;
        let expect_reply = flags & IPC_SEND_FLAG_EXPECT_REPLY != 0;
        let is_reply = flags & IPC_SEND_FLAG_IS_REPLY != 0;
        let data_len = super::read_u32_be(buf, 104)? as usize;
        // checked_add — 32-bit overflow defence.
        let total = Self::FIXED_SIZE
            .checked_add(data_len)
            .ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        // d: decode data through bufpool — acquire pooled buffer
        // copy payload bytes (memcpy only; no malloc on hit path), wrap
        // as PooledShared. At >99% pool hit rate this saves the 60 KB
        // malloc per chat_node IPC msg that previously fueled jemalloc
        // dirty-page retention.
        let mut pooled = veil_bufpool::global().acquire(data_len);
        pooled.as_vec_mut().extend_from_slice(&buf[108..total]);
        // Trailing reply fields: present only on reply-channel-aware clients.
        // Absent (older client) → default to 0 (= "no reply").
        let reply_id = if buf.len() >= total + 8 {
            super::read_u64_be(buf, total)?
        } else {
            0
        };
        let reply_endpoint_id = if buf.len() >= total + 12 {
            super::read_u32_be(buf, total + 8)?
        } else {
            0
        };
        Ok(Self {
            dst_node_id,
            src_app_id,
            app_id,
            endpoint_id,
            require_ack,
            anonymous,
            anonymous_authenticated,
            expect_reply,
            is_reply,
            reply_id,
            reply_endpoint_id,
            data: pooled.into_shared(),
        })
    }
}

// ── Stream payloads ───────────────────────────────────────────────────────── // UNSTABLE (experimental; wire format may change)

/// Default initial receive window (256 KiB).
pub const STREAM_INITIAL_WINDOW: u32 = 256 * 1024;

/// Hard cap on a peer-advertised stream window (16 MiB = 64× the default).
///
/// `initial_window` and STREAM_WINDOW increments arrive over the wire from a
/// (semi-trusted, uid-gated) IPC peer. Memory is already bounded by the
/// per-endpoint bounded channel, so an over-large window is not a memory-DoS
/// — but clamping the advisory flow-control counter to a sane ceiling keeps
/// the window layer from being trivially defeated (a peer advertising
/// `u32::MAX` would otherwise disable A→B flow control entirely). Clamping
/// (not rejecting) never affects legitimate clients, which use the 256 KiB
/// default.
pub const MAX_STREAM_INITIAL_WINDOW: u32 = 16 * 1024 * 1024;

/// Sent by IPC client to open a stream to a remote endpoint.
///
/// Wire layout:
/// ```text
/// [0..32] dst_node_id [u8; 32]
/// [32..64] app_id [u8; 32]
/// [64..68] endpoint_id u32 BE
/// [68..72] initial_window u32 BE — receive window advertised by opener
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpenPayload {
    /// Destination `node_id`.
    pub dst_node_id: [u8; 32],
    /// Destination `app_id`.
    pub app_id: [u8; 32],
    /// Destination endpoint id.
    pub endpoint_id: u32,
    /// Initial receive window advertised by the opener.
    pub initial_window: u32,
}

impl StreamOpenPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 32 + 4 + 4;

    /// Encode to the fixed 72-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.dst_node_id);
        buf[32..64].copy_from_slice(&self.app_id);
        buf[64..68].copy_from_slice(&self.endpoint_id.to_be_bytes());
        buf[68..72].copy_from_slice(&self.initial_window.to_be_bytes());
        buf
    }

    /// Parse from a 72-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            dst_node_id: super::read_array::<32>(buf, 0)?,
            app_id: super::read_array::<32>(buf, 32)?,
            endpoint_id: super::read_u32_be(buf, 64)?,
            initial_window: super::read_u32_be(buf, 68)?,
        })
    }
}

/// Sent by node to confirm stream opening.
///
/// Wire layout:
/// ```text
/// [0..4] stream_id u32 BE
/// [4..8] initial_window u32 BE — acceptor's receive window
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpenOkPayload {
    /// Node-assigned stream id for subsequent frames.
    pub stream_id: u32,
    /// Acceptor's initial receive window.
    pub initial_window: u32,
}

impl StreamOpenOkPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 4 + 4;

    /// Encode to the fixed 8-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..4].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[4..8].copy_from_slice(&self.initial_window.to_be_bytes());
        buf
    }

    /// Parse from an 8-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            stream_id: super::read_u32_be(buf, 0)?,
            initial_window: super::read_u32_be(buf, 4)?,
        })
    }
}

/// **Inbound stream notification** — daemon → bound app.
///
/// Sent when a remote peer opens a stream to a bound endpoint owned
/// by this IPC client.  The SDK uses `app_id` + `endpoint_id` to route
/// the notification to the right `AppHandle`'s inbound queue.
///
/// Wire layout (fixed 76 bytes):
/// ```text
/// [0..4]   stream_id u32 BE
/// [4..36]  app_id [u8; 32]
/// [36..40] endpoint_id u32 BE
/// [40..72] src_node_id [u8; 32]
/// [72..76] initial_window u32 BE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpenInboundPayload {
    /// Node-assigned stream id.
    pub stream_id: u32,
    /// App_id of the local bound endpoint that owns this stream.
    pub app_id: [u8; 32],
    /// Endpoint_id within the bound app.
    pub endpoint_id: u32,
    /// Node_id of the remote peer that opened the stream.
    pub src_node_id: [u8; 32],
    /// Initiator's initial receive window (us → them).
    pub initial_window: u32,
}

impl StreamOpenInboundPayload {
    /// Fixed wire size: 4 + 32 + 4 + 32 + 4.
    pub const WIRE_SIZE: usize = 4 + 32 + 4 + 32 + 4;

    /// Encode to the fixed 76-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..4].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[4..36].copy_from_slice(&self.app_id);
        buf[36..40].copy_from_slice(&self.endpoint_id.to_be_bytes());
        buf[40..72].copy_from_slice(&self.src_node_id);
        buf[72..76].copy_from_slice(&self.initial_window.to_be_bytes());
        buf
    }

    /// Parse from a 76-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let stream_id = super::read_u32_be(buf, 0)?;
        let mut app_id = [0u8; 32];
        app_id.copy_from_slice(&buf[4..36]);
        let endpoint_id = super::read_u32_be(buf, 36)?;
        let mut src_node_id = [0u8; 32];
        src_node_id.copy_from_slice(&buf[40..72]);
        let initial_window = super::read_u32_be(buf, 72)?;
        Ok(Self {
            stream_id,
            app_id,
            endpoint_id,
            src_node_id,
            initial_window,
        })
    }
}

/// Error codes for `STREAM_OPEN_ERR`.
pub mod stream_open_err {
    /// Destination endpoint not bound.
    pub const NOT_FOUND: u16 = 1;
    /// Acceptor refused the open request.
    pub const REFUSED: u16 = 2;
    /// Acceptor's receive window is fully consumed.
    pub const WINDOW_EXHAUSTED: u16 = 3;
    /// Global stream table is full (`MAX_TOTAL_STREAMS` reached).
    pub const CAPACITY_REACHED: u16 = 4;
    /// Destination `dst_node_id` is not the local daemon's node, and
    /// inter-node IPC stream-forwarding is not yet implemented in this
    /// daemon. The VeilConnector path (used by oproxy / proxy)
    /// works fine for cross-node streams; this code surfaces ONLY
    /// for the `STREAM_OPEN` IPC frame on a remote endpoint.
    ///
    /// Distinct from `NOT_FOUND` so that SDK clients can tell "you
    /// asked for a node we just don't talk to from IPC yet" apart from
    /// "the endpoint really isn't bound anywhere on the network."
    ///
    /// Re-open trigger: implement Phase 1 of the IPC stream-forwarding
    /// plan (see `docs/en/PLAN_IPC_STREAM_FORWARDING.md`).
    pub const REMOTE_NOT_IMPLEMENTED: u16 = 5;
    /// Cross-node `STREAM_OPEN`: no active session/route to `dst_node_id`, so
    /// the `AppOpen` could not be sent. Distinct from `NOT_FOUND` (which means
    /// the endpoint is not bound) — here we never reached the node at all.
    pub const NO_SESSION: u16 = 6;
    /// Cross-node `STREAM_OPEN`: the `AppOpen` was sent but no `AppReceipt`
    /// arrived from `dst_node_id` within the open-receipt timeout.
    pub const REMOTE_TIMEOUT: u16 = 7;
}

/// Sent by node when stream opening fails.
///
/// Wire layout: `[0..2] error_code u16 BE`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpenErrPayload {
    /// Code [`stream_open_err`].
    pub error_code: u16,
}

impl StreamOpenErrPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 2;

    /// Encode to a 2-byte big-endian buffer.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.error_code.to_be_bytes()
    }

    /// Parse from a 2-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            error_code: super::read_u16_be(buf, 0)?,
        })
    }
}

/// Stream data frame (bidirectional).
///
/// Wire layout:
/// ```text
/// [0..4] stream_id u32 BE
/// [4..8] data_len u32 BE
/// [8..8+data_len] data bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamDataPayload {
    /// Stream id this frame belongs to.
    pub stream_id: u32,
    /// Payload bytes.
    pub data: Vec<u8>,
}

impl StreamDataPayload {
    const FIXED_SIZE: usize = 4 + 4;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + self.data.len());
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Parse a `StreamDataPayload` from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let stream_id = super::read_u32_be(buf, 0)?;
        let data_len = super::read_u32_be(buf, 4)? as usize;
        // checked_add — 32-bit overflow defence.
        let total = Self::FIXED_SIZE
            .checked_add(data_len)
            .ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            stream_id,
            data: buf[8..total].to_vec(),
        })
    }
}

/// Close a stream (bidirectional).
///
/// Wire layout: `[0..4] stream_id u32 BE`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamClosePayload {
    /// Stream id being closed.
    pub stream_id: u32,
}

impl StreamClosePayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 4;

    /// Encode to a 4-byte big-endian buffer.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.stream_id.to_be_bytes()
    }

    /// Parse from a 4-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            stream_id: super::read_u32_be(buf, 0)?,
        })
    }
}

/// Backpressure window update (node → client).
///
/// Wire layout:
/// ```text
/// [0..4] stream_id u32 BE
/// [4..8] increment u32 BE — bytes the sender may now send
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamWindowPayload {
    /// Stream id the credit applies to.
    pub stream_id: u32,
    /// Additional bytes of receive window granted.
    pub increment: u32,
}

impl StreamWindowPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 4 + 4;

    /// Encode to the fixed 8-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..4].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[4..8].copy_from_slice(&self.increment.to_be_bytes());
        buf
    }

    /// Parse from an 8-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            stream_id: super::read_u32_be(buf, 0)?,
            increment: super::read_u32_be(buf, 4)?,
        })
    }
}

/// Error codes for `APP_SEND` responses.
pub mod ipc_send_err {
    /// Client is sending too fast — try again later.
    pub const RATE_LIMITED: u16 = 1;
    /// No active OVL1 session to the destination node — message not delivered.
    pub const NO_ROUTE: u16 = 2;
    /// E2E encryption key for the destination is not yet available.
    /// The node has a route but could not obtain the recipient's ML-KEM public
    /// key (e.g. the destination is unreachable for ROUTE_REQUEST/RESPONSE).
    /// The application should retry after a short back-off.
    pub const NO_E2E_KEY: u16 = 3;
    /// The `src_app_id` in the send request does not match any endpoint bound
    /// by this IPC connection. Prevents an application from spoofing another
    /// app's identity.
    pub const SPOOFED_SRC: u16 = 4;
    /// No active veil session to the destination — RT frame not delivered.
    /// Returned by `APP_RT_SEND` when the destination node is not reachable
    /// via any open session in the registry. The caller may retry after
    /// a short back-off once a session is established.
    pub const NO_SESSION: u16 = 5;
    /// payload size exceeds `MAX_APP_PAYLOAD_BYTES`.
    /// The application must split the message into smaller chunks before
    /// sending; the server rejects the entire frame to bound the worst-case
    /// E2E encryption / fragmentation cost on the IPC server.
    pub const PAYLOAD_TOO_LARGE: u16 = 6;
    /// Authenticated anonymous send requested but no sovereign identity is
    /// loaded — the message cannot be signed. (`anonymous_authenticated`.)
    pub const NO_IDENTITY: u16 = 7;
    /// Authenticated anonymous send: the recipient has no resolvable, valid
    /// RendezvousAd — it has not opted in to receiving (or its ad is stale).
    pub const NO_RENDEZVOUS: u16 = 8;
    /// Conflicting flags: `anonymous` (meta-E2E) and `anonymous_authenticated`
    /// (onion) are mutually exclusive transports.
    pub const INVALID_FLAGS: u16 = 9;
    /// Reply send (`is_reply`): the `reply_id` is unknown, already consumed, or
    /// its one-time reply block expired (default 300 s TTL). The app must obtain
    /// a fresh `reply_id` from a newer inbound message.
    pub const REPLY_UNKNOWN: u16 = 10;
}

// ── RegisterOnionServicePayload ──────────────────────────────────────────────

/// App → daemon request to host a LOCATION-anonymous (onion) service. Wire is
/// just the circuit `hop_count` (u32 BE; clamped to ≥ 2 by the daemon).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterOnionServicePayload {
    pub hop_count: u32,
}

impl RegisterOnionServicePayload {
    pub fn encode(&self) -> [u8; 4] {
        self.hop_count.to_be_bytes()
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        Ok(Self {
            hop_count: super::read_u32_be(buf, 0)?,
        })
    }
}

// ── RegisterRendezvousPublisherPayload ───────────────────────────────────────

/// App → daemon request to register a PLAIN rendezvous-publisher entry that
/// advertises the relay's KEM key (mailbox-by-discovery). The maintenance tick
/// then signs + publishes a v5 `RendezvousAd` under this node's real id.
///
/// Wire layout (BE integers):
///   rendezvous_node_id:   [u8; 32]
///   auth_cookie:          [u8; 16]
///   validity_window_secs: u64
///   relay_kem_algo:       u8
///   relay_kem_pk_len:     u16, relay_kem_pk: [u8; len]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRendezvousPublisherPayload {
    pub rendezvous_node_id: [u8; 32],
    pub auth_cookie: [u8; 16],
    pub validity_window_secs: u64,
    pub relay_kem_algo: u8,
    pub relay_kem_pk: Vec<u8>,
}

impl RegisterRendezvousPublisherPayload {
    /// Fixed prefix size before the variable-length KEM pubkey.
    pub const HEADER_SIZE: usize = 32 + 16 + 8 + 1 + 2;

    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.relay_kem_pk.len() <= MAX_RENDEZVOUS_KEM_PK_BYTES);
        let kem_len = self.relay_kem_pk.len().min(u16::MAX as usize);
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + kem_len);
        buf.extend_from_slice(&self.rendezvous_node_id);
        buf.extend_from_slice(&self.auth_cookie);
        buf.extend_from_slice(&self.validity_window_secs.to_be_bytes());
        buf.push(self.relay_kem_algo);
        buf.extend_from_slice(&(kem_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.relay_kem_pk[..kem_len]);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let rendezvous_node_id = super::read_array::<32>(buf, 0)?;
        let auth_cookie = super::read_array::<16>(buf, 32)?;
        let validity_window_secs = super::read_u64_be(buf, 48)?;
        let relay_kem_algo = buf[56];
        let kem_len = super::read_u16_be(buf, 57)? as usize;
        if kem_len > MAX_RENDEZVOUS_KEM_PK_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "register_rendezvous_publisher.relay_kem_pk_len",
                value: kem_len as u64,
                max: MAX_RENDEZVOUS_KEM_PK_BYTES as u64,
            });
        }
        let kem_end = Self::HEADER_SIZE + kem_len;
        if buf.len() < kem_end {
            return Err(ProtoError::BufferTooShort {
                need: kem_end,
                got: buf.len(),
            });
        }
        Ok(Self {
            rendezvous_node_id,
            auth_cookie,
            validity_window_secs,
            relay_kem_algo,
            relay_kem_pk: buf[Self::HEADER_SIZE..kem_end].to_vec(),
        })
    }
}

// ── SendToOnionServicePayload ────────────────────────────────────────────────

/// App → daemon request to send to a LOCATION-anonymous service addressed by its
/// Ed25519 IDENTITY key (the daemon resolves the per-period blinded descriptor).
///
/// `anonymous` selects the delivery mode: `false` = AUTHENTICATED (the daemon
/// signs with our sovereign identity; the service learns + verifies our
/// node_id), `true` = ANONYMOUS (the service receives `src_node_id = [0;32]` and
/// never learns the sender). `src_app_id` is only meaningful for the anonymous
/// mode (it rides inside the sealed payload for the service's app-level routing);
/// the authenticated mode ignores it.
///
/// Wire layout:
/// ```text
/// [0..32]   service_identity_vk [u8; 32]   service Ed25519 identity ("address")
/// [32..64]  target_app_id [u8; 32]
/// [64..68]  target_endpoint_id u32 BE
/// [68..72]  hop_count u32 BE               circuit length; daemon clamps to ≥ 2
/// [72]      flags u8                       bit0 = anonymous (unauthenticated)
/// [73..105] src_app_id [u8; 32]            anonymous mode only
/// [105..]   data                            opaque payload (tail)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendToOnionServicePayload {
    pub service_identity_vk: [u8; 32],
    pub target_app_id: [u8; 32],
    pub target_endpoint_id: u32,
    pub hop_count: u32,
    pub anonymous: bool,
    pub src_app_id: [u8; 32],
    pub data: Vec<u8>,
}

impl SendToOnionServicePayload {
    pub const FIXED_SIZE: usize = 32 + 32 + 4 + 4 + 1 + 32; // 105
    const FLAG_ANONYMOUS: u8 = 0x01;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::FIXED_SIZE + self.data.len());
        out.extend_from_slice(&self.service_identity_vk);
        out.extend_from_slice(&self.target_app_id);
        out.extend_from_slice(&self.target_endpoint_id.to_be_bytes());
        out.extend_from_slice(&self.hop_count.to_be_bytes());
        out.push(if self.anonymous {
            Self::FLAG_ANONYMOUS
        } else {
            0
        });
        out.extend_from_slice(&self.src_app_id);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            service_identity_vk: super::read_array::<32>(buf, 0)?,
            target_app_id: super::read_array::<32>(buf, 32)?,
            target_endpoint_id: super::read_u32_be(buf, 64)?,
            hop_count: super::read_u32_be(buf, 68)?,
            anonymous: buf[72] & Self::FLAG_ANONYMOUS != 0,
            src_app_id: super::read_array::<32>(buf, 73)?,
            data: buf[Self::FIXED_SIZE..].to_vec(),
        })
    }
}

// ── SendAnonymousDirectPayload ───────────────────────────────────────────────

/// App → daemon request for a DIRECT (non-rendezvous) sender-anonymous send to a
/// KNOWN peer addressed by its `(target_node_id, target_x25519_pk)`. The receiver
/// sees `src_node_id = [0;32]`; `src_app_id` rides inside the sealed payload for
/// the receiver's app-level routing only.
///
/// Wire layout:
/// ```text
/// [0..32]    target_node_id [u8; 32]
/// [32..64]   target_x25519_pk [u8; 32]      receiver anonymity x25519
/// [64..96]   target_app_id [u8; 32]
/// [96..128]  src_app_id [u8; 32]
/// [128..132] target_endpoint_id u32 BE
/// [132..136] hop_count u32 BE               circuit length; daemon clamps to ≥ 1
/// [136..]    data                            opaque payload (tail)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendAnonymousDirectPayload {
    pub target_node_id: [u8; 32],
    pub target_x25519_pk: [u8; 32],
    pub target_app_id: [u8; 32],
    pub src_app_id: [u8; 32],
    pub target_endpoint_id: u32,
    pub hop_count: u32,
    pub data: Vec<u8>,
}

impl SendAnonymousDirectPayload {
    pub const FIXED_SIZE: usize = 32 + 32 + 32 + 32 + 4 + 4; // 136

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::FIXED_SIZE + self.data.len());
        out.extend_from_slice(&self.target_node_id);
        out.extend_from_slice(&self.target_x25519_pk);
        out.extend_from_slice(&self.target_app_id);
        out.extend_from_slice(&self.src_app_id);
        out.extend_from_slice(&self.target_endpoint_id.to_be_bytes());
        out.extend_from_slice(&self.hop_count.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            target_node_id: super::read_array::<32>(buf, 0)?,
            target_x25519_pk: super::read_array::<32>(buf, 32)?,
            target_app_id: super::read_array::<32>(buf, 64)?,
            src_app_id: super::read_array::<32>(buf, 96)?,
            target_endpoint_id: super::read_u32_be(buf, 128)?,
            hop_count: super::read_u32_be(buf, 132)?,
            data: buf[Self::FIXED_SIZE..].to_vec(),
        })
    }
}

// ── AppIpcRtSendPayload ─────────────────────────────────────────────────────

/// Sent by the IPC client to dispatch a real-time (RT) frame into the veil.
///
/// Wire layout:
/// ```text
/// [0..32] dst_node_id [u8; 32]
/// [32..64] src_app_id [u8; 32]
/// [64..96] dst_app_id [u8; 32]
/// [96..100] endpoint_id u32 BE
/// [100..104] seq u32 BE
/// [104..112] timestamp_us u64 BE
/// [112] marker u8
/// [113..117] payload_type u32 BE
/// [117..121] data_len u32 BE
/// [121..] data bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIpcRtSendPayload {
    /// Destination `node_id`.
    pub dst_node_id: [u8; 32],
    /// Sender's own app_id (must match a bound endpoint on this IPC connection).
    pub src_app_id: [u8; 32],
    /// Destination app_id on the remote node.
    pub dst_app_id: [u8; 32],
    /// Destination endpoint id.
    pub endpoint_id: u32,
    /// Monotonic sequence number (wraparound-safe).
    pub seq: u32,
    /// Media clock in microseconds.
    pub timestamp_us: u64,
    /// RTP-style marker bit.
    pub marker: u8,
    /// App-defined codec identifier.
    pub payload_type: u32,
    /// RT payload bytes.
    pub data: Vec<u8>,
}

impl AppIpcRtSendPayload {
    /// Size of the fixed-width header (before `data`).
    pub const FIXED_SIZE: usize = 32 + 32 + 32 + 4 + 4 + 8 + 1 + 4 + 4; // 121

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + self.data.len());
        buf.extend_from_slice(&self.dst_node_id);
        buf.extend_from_slice(&self.src_app_id);
        buf.extend_from_slice(&self.dst_app_id);
        buf.extend_from_slice(&self.endpoint_id.to_be_bytes());
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_us.to_be_bytes());
        buf.push(self.marker);
        buf.extend_from_slice(&self.payload_type.to_be_bytes());
        buf.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Parse an RT-send payload from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let dst_node_id = super::read_array::<32>(buf, 0)?;
        let src_app_id = super::read_array::<32>(buf, 32)?;
        let dst_app_id = super::read_array::<32>(buf, 64)?;
        let endpoint_id = super::read_u32_be(buf, 96)?;
        let seq = super::read_u32_be(buf, 100)?;
        let timestamp_us = super::read_u64_be(buf, 104)?;
        let marker = buf[112];
        let payload_type = super::read_u32_be(buf, 113)?;
        let data_len = super::read_u32_be(buf, 117)? as usize;
        // checked_add — 32-bit overflow defence.
        let total = Self::FIXED_SIZE
            .checked_add(data_len)
            .ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            dst_node_id,
            src_app_id,
            dst_app_id,
            endpoint_id,
            seq,
            timestamp_us,
            marker,
            payload_type,
            data: buf[Self::FIXED_SIZE..total].to_vec(),
        })
    }
}

// ── Mobile / network-state IPC payloads ────────────────

/// Foreground / background tier the app is currently in. Mapped to a
/// keepalive-cadence multiplier by the daemon — see `MobileConfig`.
///
/// Wire byte:
/// `0` = Foreground (UI active, normal cadence)
/// `1` = Active (background but UI alive — 2× longer keepalive)
/// `2` = LowPower (Doze / iOS BackgroundTask — 8× longer + route-probe paused)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MobileBackgroundMode {
    /// UI active, normal cadence.
    Foreground = 0,
    /// Background but UI alive.
    Active = 1,
    /// Doze / iOS BackgroundTask — most aggressive battery savings.
    LowPower = 2,
}

impl MobileBackgroundMode {
    /// Decode from a single wire byte.
    pub fn from_wire(b: u8) -> Result<Self, ProtoError> {
        match b {
            0 => Ok(Self::Foreground),
            1 => Ok(Self::Active),
            2 => Ok(Self::LowPower),
            _ => Err(ProtoError::ValueTooLarge {
                field: "mobile_background_mode",
                value: b as u64,
                max: 2,
            }),
        }
    }

    /// Wire byte representation.
    pub fn to_wire(self) -> u8 {
        self as u8
    }

    /// True iff this tier should suppress background work (route probes
    /// PEX walks, DHT republish) to preserve battery. Only `LowPower`
    /// triggers full suspension; `Active` keeps maintenance running but
    /// stretches keepalive.
    pub fn pauses_background_work(self) -> bool {
        matches!(self, Self::LowPower)
    }
}

/// Payload [`crate::family::LocalAppMsg::SetPushEnvelope`] (
/// — T1.2). App registers a sealed FCM/APNs token envelope with
/// the daemon, scoped to a specific rendezvous publication.
///
/// Wire layout:
/// ```text
/// [0..32] rendezvous_node_id — matches an entry already registered via
/// `register_rendezvous_publisher_with_push`
/// [32..48] auth_cookie — same `(rendezvous, cookie)` tuple disambiguates
/// multiple publications with the same rendezvous
/// [48..50] envelope_len u16 BE — 0 = clear push registration
/// [50..] envelope — sealed FCM/APNs token; up to MAX_PUSH_ENVELOPE_LEN
/// ```
///
/// Sealing happens client-side BEFORE this payload reaches the daemon —
/// the daemon never sees the underlying token, only opaque ciphertext
/// bytes. See `veil_anonymity::push_envelope::seal_push_envelope`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetPushEnvelopePayload {
    pub rendezvous_node_id: [u8; 32],
    pub auth_cookie: [u8; 16],
    pub envelope: Vec<u8>,
}

/// Mirror of `veil_anonymity::push_envelope::MAX_PUSH_ENVELOPE_LEN` —
/// kept here so the proto layer is self-contained and can defend the
/// wire-decode path without depending on the anonymity crate.
pub const MAX_PUSH_ENVELOPE_BYTES: usize = 512;

impl SetPushEnvelopePayload {
    /// Minimum wire size: header without envelope body.
    pub const MIN_WIRE_SIZE: usize = 32 + 16 + 2;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::MIN_WIRE_SIZE + self.envelope.len());
        out.extend_from_slice(&self.rendezvous_node_id);
        out.extend_from_slice(&self.auth_cookie);
        out.extend_from_slice(&(self.envelope.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.envelope);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::MIN_WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::MIN_WIRE_SIZE,
                got: buf.len(),
            });
        }
        let mut rendezvous_node_id = [0u8; 32];
        rendezvous_node_id.copy_from_slice(&buf[..32]);
        let mut auth_cookie = [0u8; 16];
        auth_cookie.copy_from_slice(&buf[32..48]);
        let envelope_len = u16::from_be_bytes([buf[48], buf[49]]) as usize;
        if envelope_len > MAX_PUSH_ENVELOPE_BYTES {
            return Err(ProtoError::Malformed(format!(
                "push_envelope: envelope_len {envelope_len} > MAX_PUSH_ENVELOPE_BYTES {MAX_PUSH_ENVELOPE_BYTES}"
            )));
        }
        // cluster pattern: checked_add for 32-bit safety.
        let total =
            Self::MIN_WIRE_SIZE
                .checked_add(envelope_len)
                .ok_or(ProtoError::BufferTooShort {
                    need: usize::MAX,
                    got: buf.len(),
                })?;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        let envelope = buf[Self::MIN_WIRE_SIZE..total].to_vec();
        Ok(Self {
            rendezvous_node_id,
            auth_cookie,
            envelope,
        })
    }
}

/// Reply status [`SetPushEnvelopePayload`].
///
/// Wire byte:
/// * `0` — OK (envelope set OR cleared)
/// * `1` — NoMatchingRendezvous (no `(rendezvous_node_id, auth_cookie)` registered)
/// * `2` — EnvelopeTooLarge (caller-side wire-format error)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetPushEnvelopeStatus {
    Ok = 0,
    NoMatchingRendezvous = 1,
    EnvelopeTooLarge = 2,
}

impl SetPushEnvelopeStatus {
    pub fn from_wire(b: u8) -> Result<Self, ProtoError> {
        match b {
            0 => Ok(Self::Ok),
            1 => Ok(Self::NoMatchingRendezvous),
            2 => Ok(Self::EnvelopeTooLarge),
            _ => Err(ProtoError::Malformed(format!(
                "set_push_envelope: unknown status {b}"
            ))),
        }
    }
}

// ── SetWakeHmacEnvelope (Epic 489.10 slice 4.3.4) ──────────────────────────

/// Mirror of `veil_anonymity::rendezvous::MAX_WAKE_HMAC_ENVELOPE_LEN`.
/// Kept here so the proto layer can defend the wire-decode path without
/// depending on the anonymity crate.
pub const MAX_WAKE_HMAC_ENVELOPE_BYTES: usize = 128;

/// Mirror of `veil_anonymity::rendezvous::MAX_RENDEZVOUS_KEM_PK_LEN`.
/// Bounds the v5 relay-KEM-pubkey trailer on the `ReplicaWire` decode path
/// (fits ML-KEM-768 with slack) without depending on the anonymity crate.
pub const MAX_RENDEZVOUS_KEM_PK_BYTES: usize = 2048;

/// Payload [`crate::family::LocalAppMsg::SetWakeHmacEnvelope`].  Receiver
/// app uploads the sealed wake-HMAC envelope so the daemon embeds it in
/// every subsequent signed RendezvousAd refresh.
///
/// Wire layout (identical to [`SetPushEnvelopePayload`] modulo the cap):
/// ```text
/// [0..32]  rendezvous_node_id
/// [32..48] auth_cookie
/// [48..50] envelope_len u16 BE — 0 = clear wake-HMAC registration
/// [50..]   envelope — sealed WakeHmacKey; up to MAX_WAKE_HMAC_ENVELOPE_BYTES
/// ```
///
/// Sealing happens client-side (`VeilPush.sealWakeHmacKey` → existing
/// push-envelope seal primitive) BEFORE this payload reaches the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetWakeHmacEnvelopePayload {
    pub rendezvous_node_id: [u8; 32],
    pub auth_cookie: [u8; 16],
    pub envelope: Vec<u8>,
}

impl SetWakeHmacEnvelopePayload {
    pub const MIN_WIRE_SIZE: usize = 32 + 16 + 2;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::MIN_WIRE_SIZE + self.envelope.len());
        out.extend_from_slice(&self.rendezvous_node_id);
        out.extend_from_slice(&self.auth_cookie);
        out.extend_from_slice(&(self.envelope.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.envelope);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::MIN_WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::MIN_WIRE_SIZE,
                got: buf.len(),
            });
        }
        let mut rendezvous_node_id = [0u8; 32];
        rendezvous_node_id.copy_from_slice(&buf[..32]);
        let mut auth_cookie = [0u8; 16];
        auth_cookie.copy_from_slice(&buf[32..48]);
        let envelope_len = u16::from_be_bytes([buf[48], buf[49]]) as usize;
        if envelope_len > MAX_WAKE_HMAC_ENVELOPE_BYTES {
            return Err(ProtoError::Malformed(format!(
                "wake_hmac_envelope: envelope_len {envelope_len} > MAX_WAKE_HMAC_ENVELOPE_BYTES {MAX_WAKE_HMAC_ENVELOPE_BYTES}"
            )));
        }
        let total =
            Self::MIN_WIRE_SIZE
                .checked_add(envelope_len)
                .ok_or(ProtoError::BufferTooShort {
                    need: usize::MAX,
                    got: buf.len(),
                })?;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        let envelope = buf[Self::MIN_WIRE_SIZE..total].to_vec();
        Ok(Self {
            rendezvous_node_id,
            auth_cookie,
            envelope,
        })
    }
}

/// Reply status [`SetWakeHmacEnvelopePayload`].  Same shape as
/// [`SetPushEnvelopeStatus`] for consistency.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetWakeHmacEnvelopeStatus {
    Ok = 0,
    NoMatchingRendezvous = 1,
    EnvelopeTooLarge = 2,
}

impl SetWakeHmacEnvelopeStatus {
    pub fn from_wire(b: u8) -> Result<Self, ProtoError> {
        match b {
            0 => Ok(Self::Ok),
            1 => Ok(Self::NoMatchingRendezvous),
            2 => Ok(Self::EnvelopeTooLarge),
            _ => Err(ProtoError::Malformed(format!(
                "set_wake_hmac_envelope: unknown status {b}"
            ))),
        }
    }
}

// ── Mailbox put/fetch/ack ────────────────

/// Maximum size of a single mailbox blob on the wire. Mirrors
/// [`veil-mailbox::MAX_BLOB_BYTES`]. Hardcoded here to avoid a
/// dependency on `veil-mailbox` from the proto crate (proto must
/// stay leaf-light, see [`crate::lib`] doc).
pub const MAX_MAILBOX_BLOB_BYTES: usize = 1024 * 1024;

/// Maximum count of blobs returned in one [`MailboxFetchRespPayload`].
/// Bounds frame size (~256 KiB on average if we hit cap with full
/// 1-MiB blobs would blow `MAX_FRAME_BODY` — at 256 entries × 4 KiB
/// avg the typical frame is ~1 MiB, well under the IPC limit).
pub const MAX_MAILBOX_FETCH_ENTRIES: usize = 256;

/// Authentication-cookie length (matches `RendezvousPublisherEntry.auth_cookie`).
pub const MAILBOX_AUTH_COOKIE_LEN: usize = 16;

/// max bytes for the optional capability-
/// token trailer. Mirrors `veil-mailbox::MAX_CAPABILITY_TOKEN_BYTES`.
/// 2 KiB fits Falcon-512 worst-case (~1.6 KiB) with headroom. Hardcoded
/// here to keep `veil-proto` a leaf crate (no dep on veil-mailbox).
pub const MAX_MAILBOX_CAPABILITY_TOKEN_BYTES: usize = 2048;

/// Payload [`crate::family::LocalAppMsg::MailboxPut`].
///
/// Wire layout:
/// ```text
/// [0..32] receiver_id [u8; 32]
/// [32..64] content_id [u8; 32]
/// [64..96] sender_id [u8; 32]
/// [96..100] blob_len u32 BE (≤ MAX_MAILBOX_BLOB_BYTES)
/// [100..100+blob_len] blob bytes (opaque encrypted payload)
///
/// // Optional trailer:
/// [N] envelope_len u16 BE (0 = no push wake)
/// [N+2..N+2+env_len] push_envelope bytes (sealed FCM/APNs token
/// ≤ MAX_PUSH_ENVELOPE_BYTES)
///
/// // Optional trailer:
/// [M] cap_token_len u16 BE (0 = no token)
/// [M+2..M+2+cap_len] cap_token bytes (receiver-signed
/// MailboxCapabilityToken
/// ≤ MAX_MAILBOX_CAPABILITY_TOKEN_BYTES)
///
/// // Optional trailer (Epic 489.10 slice 4.3.4 follow-up):
/// [O] wake_hmac_env_len u16 BE (0 = sender did not forward HMAC envelope)
/// [O+2..O+2+wake_env_len] wake_hmac_envelope bytes (sealed
/// WakeHmacKey ≤ MAX_WAKE_HMAC_ENVELOPE_BYTES)
/// ```
///
/// **Push envelope** is optional. When non-empty, the relay (after
/// successful storage) unseals it with its X25519 secret to recover
/// the FCM/APNs token, then dispatches a push notification to wake
/// the offline receiver. Empty / absent → relay only stores the blob;
/// receiver picks it up on next online cycle.
///
/// **Capability token** is optional on the wire but the relay
/// can require it via `MailboxConfig::require_capability_token`. Token
/// is signed by the receiver's identity key and proves "the receiver
/// authorised deposits to its own mailbox". Sender obtains the token
/// from the receiver's `RendezvousAd`.
/// Pre-slice-1 senders emit no token; relays running with the policy
/// gate flipped to `false` (the default) accept those puts unchanged.
///
/// **Backward compatibility:** both trailers are optional. Old senders
/// emit either or both at length-zero / absent; new senders emit both
/// trailer-length fields with zero defaults. Old daemons receiving a
/// new sender's payload ignore the trailing bytes (length is bounded
/// by `MAX_FRAME_BODY`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxPutPayload {
    /// Target receiver's `node_id`.
    pub receiver_id: [u8; 32],
    /// Caller-chosen content id (recommended: BLAKE3 of plaintext) used
    /// for dedup at the relay and [`MailboxAckPayload`].
    pub content_id: [u8; 32],
    /// Sender's `node_id` — recorded with the blob for receiver's
    /// peer-sync logic (P4).
    pub sender_id: [u8; 32],
    /// Encrypted blob. The relay does not interpret this; the receiver
    /// decrypts it after fetch.
    pub blob: Vec<u8>,
    /// Optional sealed push envelope. Sender
    /// reads this from the receiver's DHT-published `RendezvousAd`
    /// and forwards it here. Relay unseals with its X25519 sk to
    /// recover the FCM/APNs token and dispatches a wake push. `None`
    /// = receiver did not register push (e.g. desktop client) —
    /// relay only stores.
    pub push_envelope: Option<Vec<u8>>,
    /// optional opaque capability-token
    /// bytes. Decoded and verified by `veil-mailbox`'s
    /// `Mailbox::put_with_capability` against the receiver's identity
    /// pubkey. `None` = sender omitted the token (legacy senders
    /// or relays running with `require_capability_token = false`).
    pub capability_token: Option<Vec<u8>>,
    /// Optional sealed wake-HMAC envelope copied verbatim from the
    /// receiver's RendezvousAd `wake_hmac_envelope` field (slice 4.3.2).
    /// Relay (if it decided to fire a push wake) unseals it with its
    /// X25519 sk to recover the receiver's WakeHmacKey, then mints
    /// an HMAC tag over the wake payload before dispatching the FCM
    /// / APNs delivery — receiver's plugin verifies the tag locally
    /// and aborts wake on mismatch (closes leaked-push-token DoS /
    /// presence-oracle vector).
    ///
    /// `None` = sender did not propagate the envelope (legacy sender,
    /// or receiver did not register for wake-HMAC).  Cap
    /// [`MAX_WAKE_HMAC_ENVELOPE_BYTES`].
    ///
    /// NOTE (audit cycle-6, P7): this is the sender→relay PROPAGATION channel
    /// (489.10 slice 4.3.4). The relay-side CONSUMER — unseal + mint + attach —
    /// is the deferred push-relay epic (TASKS.md T3 / 489.10 slice 4.4), so
    /// today the relay deposit handlers decode this field but do NOT yet forward
    /// it to the push path. That is intentional forward-wiring, not a gap or a
    /// vestigial field: senders populate it now so no wire change is needed when
    /// the relay mint ships.
    pub wake_hmac_envelope: Option<Vec<u8>>,
}

impl MailboxPutPayload {
    /// Header size before the variable-length blob.
    pub const HEADER_SIZE: usize = 32 + 32 + 32 + 4;

    /// Encode to wire bytes. Caller is responsible for the blob size
    /// staying ≤ [`MAX_MAILBOX_BLOB_BYTES`], the envelope size
    /// staying ≤ [`MAX_PUSH_ENVELOPE_BYTES`], and the capability token
    /// staying ≤ [`MAX_MAILBOX_CAPABILITY_TOKEN_BYTES`].
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.blob.len() <= MAX_MAILBOX_BLOB_BYTES);
        debug_assert!(self.blob.len() <= u32::MAX as usize);
        let env_len = self.push_envelope.as_ref().map(|e| e.len()).unwrap_or(0);
        debug_assert!(env_len <= MAX_PUSH_ENVELOPE_BYTES);
        let cap_len = self.capability_token.as_ref().map(|t| t.len()).unwrap_or(0);
        debug_assert!(cap_len <= MAX_MAILBOX_CAPABILITY_TOKEN_BYTES);
        let wake_env_len = self
            .wake_hmac_envelope
            .as_ref()
            .map(|e| e.len())
            .unwrap_or(0);
        debug_assert!(wake_env_len <= MAX_WAKE_HMAC_ENVELOPE_BYTES);
        let mut buf = Vec::with_capacity(
            Self::HEADER_SIZE + self.blob.len() + 2 + env_len + 2 + cap_len + 2 + wake_env_len,
        );
        buf.extend_from_slice(&self.receiver_id);
        buf.extend_from_slice(&self.content_id);
        buf.extend_from_slice(&self.sender_id);
        buf.extend_from_slice(&(self.blob.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.blob);
        // Trailer 1 (push_envelope): always emit envelope_len (0 = absent)
        // so new decoders have a stable parse path. Old decoders stop at
        // the blob and ignore the trailing bytes.
        buf.extend_from_slice(&(env_len as u16).to_be_bytes());
        if let Some(env) = self.push_envelope.as_ref() {
            buf.extend_from_slice(env);
        }
        // Trailer 2 (capability_token): same
        // shape — always emit cap_len (0 = absent). Old decoders stop
        // after Trailer 1 and ignore these trailing bytes.
        buf.extend_from_slice(&(cap_len as u16).to_be_bytes());
        if let Some(token) = self.capability_token.as_ref() {
            buf.extend_from_slice(token);
        }
        // Trailer 3 (wake_hmac_envelope, Epic 489.10 slice 4.3.4 follow-up):
        // sealed `WakeHmacKey` forwarded copy-paste from the receiver's
        // RendezvousAd.  Same length-prefix-then-bytes shape; legacy
        // decoders stop after Trailer 2 and ignore these bytes.
        buf.extend_from_slice(&(wake_env_len as u16).to_be_bytes());
        if let Some(env) = self.wake_hmac_envelope.as_ref() {
            buf.extend_from_slice(env);
        }
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let receiver_id = super::read_array::<32>(buf, 0)?;
        let content_id = super::read_array::<32>(buf, 32)?;
        let sender_id = super::read_array::<32>(buf, 64)?;
        let blob_len = super::read_u32_be(buf, 96)? as usize;
        if blob_len > MAX_MAILBOX_BLOB_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "mailbox_put.blob_len",
                value: blob_len as u64,
                max: MAX_MAILBOX_BLOB_BYTES as u64,
            });
        }
        let blob_end = Self::HEADER_SIZE
            .checked_add(blob_len)
            .ok_or(ProtoError::Malformed(
                "mailbox_put: header + blob_len overflow".to_owned(),
            ))?;
        if buf.len() < blob_end {
            return Err(ProtoError::BufferTooShort {
                need: blob_end,
                got: buf.len(),
            });
        }
        let blob = buf[Self::HEADER_SIZE..blob_end].to_vec();
        // ── Trailer 1: optional push_envelope ────────────────────────
        // Legacy senders stop at `blob_end`.
        let mut cursor = blob_end;
        let push_envelope = if buf.len() >= cursor + 2 {
            let env_len = super::read_u16_be(buf, cursor)? as usize;
            cursor += 2;
            if env_len > MAX_PUSH_ENVELOPE_BYTES {
                return Err(ProtoError::ValueTooLarge {
                    field: "mailbox_put.push_envelope_len",
                    value: env_len as u64,
                    max: MAX_PUSH_ENVELOPE_BYTES as u64,
                });
            }
            if env_len == 0 {
                None
            } else {
                let env_end = cursor + env_len;
                if buf.len() < env_end {
                    return Err(ProtoError::BufferTooShort {
                        need: env_end,
                        got: buf.len(),
                    });
                }
                let env = buf[cursor..env_end].to_vec();
                cursor = env_end;
                Some(env)
            }
        } else {
            None
        };
        // ── Trailer 2: optional capability_token ─
        let capability_token = if buf.len() >= cursor + 2 {
            let cap_len = super::read_u16_be(buf, cursor)? as usize;
            cursor += 2;
            if cap_len > MAX_MAILBOX_CAPABILITY_TOKEN_BYTES {
                return Err(ProtoError::ValueTooLarge {
                    field: "mailbox_put.cap_token_len",
                    value: cap_len as u64,
                    max: MAX_MAILBOX_CAPABILITY_TOKEN_BYTES as u64,
                });
            }
            if cap_len == 0 {
                None
            } else {
                let cap_end = cursor + cap_len;
                if buf.len() < cap_end {
                    return Err(ProtoError::BufferTooShort {
                        need: cap_end,
                        got: buf.len(),
                    });
                }
                let token = buf[cursor..cap_end].to_vec();
                cursor = cap_end;
                Some(token)
            }
        } else {
            None
        };
        // ── Trailer 3: optional wake_hmac_envelope (slice 4.3.4 follow-up) ──
        // Legacy senders stop after Trailer 2; new senders emit a
        // length-prefixed envelope (0 = sender did not propagate).
        let wake_hmac_envelope = if buf.len() >= cursor + 2 {
            let wake_env_len = super::read_u16_be(buf, cursor)? as usize;
            cursor += 2;
            if wake_env_len > MAX_WAKE_HMAC_ENVELOPE_BYTES {
                return Err(ProtoError::ValueTooLarge {
                    field: "mailbox_put.wake_hmac_envelope_len",
                    value: wake_env_len as u64,
                    max: MAX_WAKE_HMAC_ENVELOPE_BYTES as u64,
                });
            }
            if wake_env_len == 0 {
                None
            } else {
                let wake_env_end = cursor + wake_env_len;
                if buf.len() < wake_env_end {
                    return Err(ProtoError::BufferTooShort {
                        need: wake_env_end,
                        got: buf.len(),
                    });
                }
                Some(buf[cursor..wake_env_end].to_vec())
            }
        } else {
            None
        };
        Ok(Self {
            receiver_id,
            content_id,
            sender_id,
            blob,
            push_envelope,
            capability_token,
            wake_hmac_envelope,
        })
    }
}

/// Status byte [`MailboxPutOkPayload`]. Mirrors
/// `veil_mailbox::PutOutcome` — see that crate's docs for the
/// full semantics of each variant.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxPutStatus {
    /// Stored. `evicted` may be > 0 if the global quota required
    /// evicting older blobs to fit.
    Stored = 0,
    /// Same `(receiver, content_id)` already present — no-op.
    Duplicate = 1,
    /// Receiver's per-receiver quota would have been exceeded.
    QuotaPerReceiverExceeded = 2,
    /// New blob alone exceeds the global cap — practically impossible
    /// given [`MAX_MAILBOX_BLOB_BYTES`] is much smaller.
    QuotaGlobalExceeded = 3,
    /// Sender exceeded the per-receiver rate limit.
    RateLimited = 4,
    /// Daemon is not running a mailbox (operator did not opt).
    NotMailboxRelay = 5,
    /// relay configured with
    /// `require_capability_token = true` rejected a PUT that arrived
    /// without a capability token.
    CapabilityRequired = 6,
    /// capability token decode or verify
    /// failed (expired, wrong receiver, or bad signature).
    CapabilityInvalid = 7,
    /// per-sender byte cap exceeded.
    QuotaPerSenderExceeded = 8,
}

impl MailboxPutStatus {
    /// Decode from a wire byte.
    pub fn from_wire(b: u8) -> Result<Self, ProtoError> {
        match b {
            0 => Ok(Self::Stored),
            1 => Ok(Self::Duplicate),
            2 => Ok(Self::QuotaPerReceiverExceeded),
            3 => Ok(Self::QuotaGlobalExceeded),
            4 => Ok(Self::RateLimited),
            5 => Ok(Self::NotMailboxRelay),
            6 => Ok(Self::CapabilityRequired),
            7 => Ok(Self::CapabilityInvalid),
            8 => Ok(Self::QuotaPerSenderExceeded),
            _ => Err(ProtoError::Malformed(format!(
                "mailbox_put: unknown status {b}"
            ))),
        }
    }
}

/// Payload [`crate::family::LocalAppMsg::MailboxPutOk`].
///
/// Wire layout: `[status_u8 | evicted_u32_be]` (5 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxPutOkPayload {
    /// Outcome of the put.
    pub status: MailboxPutStatus,
    /// Number of older blobs the relay had to evict to make room (only
    /// nonzero when `status == Stored` and the global quota was hit).
    pub evicted: u32,
}

impl MailboxPutOkPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 1 + 4;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.push(self.status as u8);
        buf.extend_from_slice(&self.evicted.to_be_bytes());
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let status = MailboxPutStatus::from_wire(buf[0])?;
        let evicted = super::read_u32_be(buf, 1)?;
        Ok(Self { status, evicted })
    }
}

/// Payload [`crate::family::LocalAppMsg::MailboxFetch`].
///
/// Wire layout: `[receiver_id (32) | auth_cookie (16)]` (48 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxFetchPayload {
    /// Receiver whose pending blobs are being requested.
    pub receiver_id: [u8; 32],
    /// 16-byte cookie that must match a registered `RendezvousPublisherEntry`
    /// for `receiver_id`. Without a match the relay returns an empty
    /// list — does NOT distinguish "no blobs" from "wrong cookie" so
    /// the cookie isn't a probing oracle.
    pub auth_cookie: [u8; MAILBOX_AUTH_COOKIE_LEN],
}

impl MailboxFetchPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + MAILBOX_AUTH_COOKIE_LEN;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.extend_from_slice(&self.receiver_id);
        buf.extend_from_slice(&self.auth_cookie);
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            receiver_id: super::read_array::<32>(buf, 0)?,
            auth_cookie: super::read_array::<MAILBOX_AUTH_COOKIE_LEN>(buf, 32)?,
        })
    }
}

/// One blob entry [`MailboxFetchRespPayload`].
///
/// Wire layout per entry:
/// ```text
/// [0..32] sender_id [u8; 32]
/// [32..64] content_id [u8; 32]
/// [64..72] deposited_at u64 BE (Unix seconds)
/// [72..76] blob_len u32 BE
/// [76..76+blob_len] blob bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxBlobWire {
    /// Sender's `node_id` (recorded by the relay at put-time).
    pub sender_id: [u8; 32],
    /// Caller-chosen content id (used for ack and dedup).
    pub content_id: [u8; 32],
    /// Unix-seconds deposit timestamp (set by the relay).
    pub deposited_at: u64,
    /// Encrypted payload bytes.
    pub blob: Vec<u8>,
}

impl MailboxBlobWire {
    /// Per-entry header size before the blob.
    pub const HEADER_SIZE: usize = 32 + 32 + 8 + 4;

    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.sender_id);
        buf.extend_from_slice(&self.content_id);
        buf.extend_from_slice(&self.deposited_at.to_be_bytes());
        buf.extend_from_slice(&(self.blob.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.blob);
    }

    fn decode_from(buf: &[u8], offset: usize) -> Result<(Self, usize), ProtoError> {
        if buf.len() < offset + Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: offset + Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let sender_id = super::read_array::<32>(buf, offset)?;
        let content_id = super::read_array::<32>(buf, offset + 32)?;
        let deposited_at = super::read_u64_be(buf, offset + 64)?;
        let blob_len = super::read_u32_be(buf, offset + 72)? as usize;
        if blob_len > MAX_MAILBOX_BLOB_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "mailbox_blob_wire.blob_len",
                value: blob_len as u64,
                max: MAX_MAILBOX_BLOB_BYTES as u64,
            });
        }
        let blob_start = offset
            .checked_add(Self::HEADER_SIZE)
            .ok_or(ProtoError::Malformed(
                "mailbox_blob_wire: offset overflow".to_owned(),
            ))?;
        let blob_end = blob_start
            .checked_add(blob_len)
            .ok_or(ProtoError::Malformed(
                "mailbox_blob_wire: blob_len overflow".to_owned(),
            ))?;
        if buf.len() < blob_end {
            return Err(ProtoError::BufferTooShort {
                need: blob_end,
                got: buf.len(),
            });
        }
        let blob = buf[blob_start..blob_end].to_vec();
        Ok((
            Self {
                sender_id,
                content_id,
                deposited_at,
                blob,
            },
            blob_end,
        ))
    }
}

/// Payload [`crate::family::LocalAppMsg::MailboxFetchResp`].
///
/// Wire layout:
/// ```text
/// [0..2] count u16 BE (≤ MAX_MAILBOX_FETCH_ENTRIES)
/// [2..] entries MailboxBlobWire * count
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxFetchRespPayload {
    /// Pending blobs, oldest first. Empty list = "nothing for you" or
    /// "auth_cookie did not match" — caller cannot distinguish.
    pub blobs: Vec<MailboxBlobWire>,
}

impl MailboxFetchRespPayload {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.blobs.len() <= MAX_MAILBOX_FETCH_ENTRIES);
        let mut buf = Vec::with_capacity(2 + self.blobs.len() * MailboxBlobWire::HEADER_SIZE);
        buf.extend_from_slice(&(self.blobs.len() as u16).to_be_bytes());
        for b in &self.blobs {
            b.encode_to(&mut buf);
        }
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 2 {
            return Err(ProtoError::BufferTooShort {
                need: 2,
                got: buf.len(),
            });
        }
        let count = super::read_u16_be(buf, 0)? as usize;
        if count > MAX_MAILBOX_FETCH_ENTRIES {
            return Err(ProtoError::ValueTooLarge {
                field: "mailbox_fetch_resp.count",
                value: count as u64,
                max: MAX_MAILBOX_FETCH_ENTRIES as u64,
            });
        }
        let mut blobs = Vec::with_capacity(count);
        let mut offset = 2;
        for _ in 0..count {
            let (entry, next) = MailboxBlobWire::decode_from(buf, offset)?;
            blobs.push(entry);
            offset = next;
        }
        Ok(Self { blobs })
    }
}

/// Payload [`crate::family::LocalAppMsg::MailboxAck`].
///
/// Wire layout: `[receiver_id (32) | content_id (32) | auth_cookie (16)]`
/// — 80 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxAckPayload {
    /// Receiver whose blob is being acked.
    pub receiver_id: [u8; 32],
    /// Content id of the blob to delete (must match the value used at
    /// put-time and reported back [`MailboxBlobWire::content_id`]).
    pub content_id: [u8; 32],
    /// 16-byte cookie that must match a registered rendezvous-publisher
    /// entry for `receiver_id`. Mismatch returns `removed = 0` — no
    /// distinction between "wrong cookie" and "blob not present".
    pub auth_cookie: [u8; MAILBOX_AUTH_COOKIE_LEN],
}

impl MailboxAckPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 32 + MAILBOX_AUTH_COOKIE_LEN;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.extend_from_slice(&self.receiver_id);
        buf.extend_from_slice(&self.content_id);
        buf.extend_from_slice(&self.auth_cookie);
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            receiver_id: super::read_array::<32>(buf, 0)?,
            content_id: super::read_array::<32>(buf, 32)?,
            auth_cookie: super::read_array::<MAILBOX_AUTH_COOKIE_LEN>(buf, 64)?,
        })
    }
}

// ── Outbox put / find-missing / ack ─────

/// Hard cap on the Bloom filter bytes carried inside
/// [`OutboxFindMissingPayload`]. Mirrors `veil-bloom::MAX_BITS_BYTES`.
pub const MAX_OUTBOX_BLOOM_BYTES: usize = 16 * 1024;

/// Hard cap on entries returned by [`OutboxFindMissingRespPayload`].
/// Mirrors `veil-mailbox::outbox::MAX_FIND_MISSING_RESULTS`.
pub const MAX_OUTBOX_FIND_MISSING_ENTRIES: usize = 256;

/// Payload [`crate::family::LocalAppMsg::OutboxPut`].
///
/// Wire layout:
/// ```text
/// [0..32] receiver_id [u8; 32]
/// [32..64] content_id [u8; 32]
/// [64..68] blob_len u32 BE (≤ MAX_MAILBOX_BLOB_BYTES)
/// [68..68+blob_len] blob bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxPutPayload {
    /// Receiver this entry is for.
    pub receiver_id: [u8; 32],
    /// Content id (caller-chosen).
    pub content_id: [u8; 32],
    /// Encrypted blob the sender wants to retransmit on demand.
    pub blob: Vec<u8>,
}

impl OutboxPutPayload {
    /// Header size before the variable-length blob.
    pub const HEADER_SIZE: usize = 32 + 32 + 4;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.blob.len() <= MAX_MAILBOX_BLOB_BYTES);
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.blob.len());
        buf.extend_from_slice(&self.receiver_id);
        buf.extend_from_slice(&self.content_id);
        buf.extend_from_slice(&(self.blob.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.blob);
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let receiver_id = super::read_array::<32>(buf, 0)?;
        let content_id = super::read_array::<32>(buf, 32)?;
        let blob_len = super::read_u32_be(buf, 64)? as usize;
        if blob_len > MAX_MAILBOX_BLOB_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "outbox_put.blob_len",
                value: blob_len as u64,
                max: MAX_MAILBOX_BLOB_BYTES as u64,
            });
        }
        let total = Self::HEADER_SIZE
            .checked_add(blob_len)
            .ok_or(ProtoError::Malformed(
                "outbox_put: header + blob_len overflow".to_owned(),
            ))?;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            receiver_id,
            content_id,
            blob: buf[Self::HEADER_SIZE..total].to_vec(),
        })
    }
}

/// Payload [`crate::family::LocalAppMsg::OutboxFindMissing`].
///
/// Wire layout:
/// ```text
/// [0..32] receiver_id [u8; 32]
/// [32..40] since u64 BE (Unix seconds)
/// [40..44] bloom_len u32 BE (≤ MAX_OUTBOX_BLOOM_BYTES)
/// [44..44+bloom_len] bloom_bytes encoded BloomFilter
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxFindMissingPayload {
    /// Receiver this query is about.
    pub receiver_id: [u8; 32],
    /// Earliest deposit time the requester is interested in.
    pub since: u64,
    /// Encoded `veil_bloom::BloomFilter` (caller responsible for
    /// size discipline — peers should size for their pending count).
    pub bloom: Vec<u8>,
}

impl OutboxFindMissingPayload {
    /// Header size before the variable-length bloom.
    pub const HEADER_SIZE: usize = 32 + 8 + 4;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.bloom.len() <= MAX_OUTBOX_BLOOM_BYTES);
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.bloom.len());
        buf.extend_from_slice(&self.receiver_id);
        buf.extend_from_slice(&self.since.to_be_bytes());
        buf.extend_from_slice(&(self.bloom.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.bloom);
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let receiver_id = super::read_array::<32>(buf, 0)?;
        let since = super::read_u64_be(buf, 32)?;
        let bloom_len = super::read_u32_be(buf, 40)? as usize;
        if bloom_len > MAX_OUTBOX_BLOOM_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "outbox_find_missing.bloom_len",
                value: bloom_len as u64,
                max: MAX_OUTBOX_BLOOM_BYTES as u64,
            });
        }
        let total = Self::HEADER_SIZE
            .checked_add(bloom_len)
            .ok_or(ProtoError::Malformed(
                "outbox_find_missing: overflow".to_owned(),
            ))?;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            receiver_id,
            since,
            bloom: buf[Self::HEADER_SIZE..total].to_vec(),
        })
    }
}

/// One entry [`OutboxFindMissingRespPayload`].
///
/// Wire layout per entry:
/// ```text
/// [0..32] content_id [u8; 32]
/// [32..40] deposited_at u64 BE
/// [40..44] blob_len u32 BE
/// [44..44+blob_len] blob bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntryWire {
    /// Content id (matches the put-time value).
    pub content_id: [u8; 32],
    /// Unix-seconds deposit timestamp.
    pub deposited_at: u64,
    /// Encrypted payload.
    pub blob: Vec<u8>,
}

impl OutboxEntryWire {
    /// Per-entry header size.
    pub const HEADER_SIZE: usize = 32 + 8 + 4;

    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.content_id);
        buf.extend_from_slice(&self.deposited_at.to_be_bytes());
        buf.extend_from_slice(&(self.blob.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.blob);
    }

    fn decode_from(buf: &[u8], offset: usize) -> Result<(Self, usize), ProtoError> {
        if buf.len() < offset + Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: offset + Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let content_id = super::read_array::<32>(buf, offset)?;
        let deposited_at = super::read_u64_be(buf, offset + 32)?;
        let blob_len = super::read_u32_be(buf, offset + 40)? as usize;
        if blob_len > MAX_MAILBOX_BLOB_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "outbox_entry_wire.blob_len",
                value: blob_len as u64,
                max: MAX_MAILBOX_BLOB_BYTES as u64,
            });
        }
        let blob_start = offset + Self::HEADER_SIZE;
        let blob_end = blob_start
            .checked_add(blob_len)
            .ok_or(ProtoError::Malformed(
                "outbox_entry_wire: blob_len overflow".to_owned(),
            ))?;
        if buf.len() < blob_end {
            return Err(ProtoError::BufferTooShort {
                need: blob_end,
                got: buf.len(),
            });
        }
        Ok((
            Self {
                content_id,
                deposited_at,
                blob: buf[blob_start..blob_end].to_vec(),
            },
            blob_end,
        ))
    }
}

/// Payload [`crate::family::LocalAppMsg::OutboxFindMissingResp`].
///
/// Wire layout: `[count_u16_be | OutboxEntryWire * count]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxFindMissingRespPayload {
    /// Outbox entries the receiver does not yet have, oldest first.
    pub entries: Vec<OutboxEntryWire>,
}

impl OutboxFindMissingRespPayload {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.entries.len() <= MAX_OUTBOX_FIND_MISSING_ENTRIES);
        let mut buf = Vec::with_capacity(2 + self.entries.len() * OutboxEntryWire::HEADER_SIZE);
        buf.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for e in &self.entries {
            e.encode_to(&mut buf);
        }
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 2 {
            return Err(ProtoError::BufferTooShort {
                need: 2,
                got: buf.len(),
            });
        }
        let count = super::read_u16_be(buf, 0)? as usize;
        if count > MAX_OUTBOX_FIND_MISSING_ENTRIES {
            return Err(ProtoError::ValueTooLarge {
                field: "outbox_find_missing_resp.count",
                value: count as u64,
                max: MAX_OUTBOX_FIND_MISSING_ENTRIES as u64,
            });
        }
        let mut entries = Vec::with_capacity(count);
        let mut offset = 2;
        for _ in 0..count {
            let (e, next) = OutboxEntryWire::decode_from(buf, offset)?;
            entries.push(e);
            offset = next;
        }
        Ok(Self { entries })
    }
}

/// Payload [`crate::family::LocalAppMsg::OutboxAck`].
///
/// Wire layout: `[receiver_id (32) | content_id (32)]` — 64 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxAckPayload {
    /// Receiver whose entry is being acked.
    pub receiver_id: [u8; 32],
    /// Content id of the entry to drop.
    pub content_id: [u8; 32],
}

impl OutboxAckPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 64;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.extend_from_slice(&self.receiver_id);
        buf.extend_from_slice(&self.content_id);
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            receiver_id: super::read_array::<32>(buf, 0)?,
            content_id: super::read_array::<32>(buf, 32)?,
        })
    }
}

// ── Lookup rendezvous replicas ─────────

/// Hard cap on entries returned by [`LookupRendezvousReplicasRespPayload`].
/// Sized for forward-compatibility with future K=3+ multi-key
/// publication; current single-key publication returns at most 1.
pub const MAX_RENDEZVOUS_REPLICAS: usize = 8;

/// Payload [`crate::family::LocalAppMsg::LookupRendezvousReplicas`].
///
/// Wire layout: `[receiver_id (32) | max_replicas (1)]` — 33 bytes.
///
/// `max_replicas == 0` is interpreted as "give me all you have" capped
/// at [`MAX_RENDEZVOUS_REPLICAS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupRendezvousReplicasPayload {
    /// Target receiver's `node_id`.
    pub receiver_id: [u8; 32],
    /// Caller-imposed cap on how many replicas to return. Daemon
    /// also enforces [`MAX_RENDEZVOUS_REPLICAS`] internally.
    pub max_replicas: u8,
}

impl LookupRendezvousReplicasPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 1;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.extend_from_slice(&self.receiver_id);
        buf.push(self.max_replicas);
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            receiver_id: super::read_array::<32>(buf, 0)?,
            max_replicas: buf[32],
        })
    }
}

/// Payload [`crate::family::LocalAppMsg::LookupRelayKey`].
///
/// Wire layout: `[node_id (32)]` — 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupRelayKeyPayload {
    /// Target node whose relay X25519 KEM key we want to resolve.
    pub node_id: [u8; 32],
}

impl LookupRelayKeyPayload {
    pub const WIRE_SIZE: usize = 32;

    pub fn encode(&self) -> Vec<u8> {
        self.node_id.to_vec()
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            node_id: super::read_array::<32>(buf, 0)?,
        })
    }
}

/// Payload [`crate::family::LocalAppMsg::LookupRelayKeyResp`].
///
/// Wire layout: `[present (1) | relay_x25519 (32, only if present == 1)]`.
/// `present == 0` means unresolved (DHT miss / verification failed) — no key
/// follows, indistinguishable from "node advertises no relay key".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupRelayKeyRespPayload {
    /// The verified 32-byte X25519 relay KEM key, or `None` if unresolved.
    pub relay_x25519: Option<[u8; 32]>,
}

impl LookupRelayKeyRespPayload {
    pub fn encode(&self) -> Vec<u8> {
        match self.relay_x25519 {
            Some(pk) => {
                let mut b = Vec::with_capacity(33);
                b.push(1);
                b.extend_from_slice(&pk);
                b
            }
            None => vec![0u8],
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        match buf.first() {
            Some(0) => Ok(Self { relay_x25519: None }),
            Some(1) => {
                if buf.len() < 33 {
                    return Err(ProtoError::BufferTooShort {
                        need: 33,
                        got: buf.len(),
                    });
                }
                Ok(Self {
                    relay_x25519: Some(super::read_array::<32>(buf, 1)?),
                })
            }
            _ => Err(ProtoError::Malformed(
                "lookup_relay_key_resp: bad/empty present byte".into(),
            )),
        }
    }
}

/// One replica entry returned by [`LookupRendezvousReplicasRespPayload`].
///
/// Wire layout per entry:
/// ```text
/// [0..32] relay_node_id [u8; 32]
/// [32..40] valid_until_unix u64 BE
/// [40..42] envelope_len u16 BE (≤ MAX_PUSH_ENVELOPE_BYTES)
/// [42..42+env_len] push_envelope bytes
/// // trailer:
/// [N..N+2] cap_token_len u16 BE (0 = no token)
/// [N+2..N+2+cap_len] capability_token bytes (≤ MAX_MAILBOX_CAPABILITY_TOKEN_BYTES)
/// // 3rd trailer (Epic 489.10 slice 2b):
/// [M..M+2] wake_hmac_len u16 BE (0 = no envelope)
/// [M+2..M+2+wake_len] wake_hmac_envelope bytes (≤ MAX_WAKE_HMAC_ENVELOPE_BYTES)
/// ```
///
/// Backward compat: pre-slice-2 daemons emit only the env trailer. New
/// decoders see no cap_token bytes after env and default
/// `capability_token = vec![]`. Likewise, pre-slice-2b daemons emit only
/// the env + cap_token trailers; new decoders see no wake_hmac bytes after
/// cap_token and default `wake_hmac_envelope = vec![]`. The 3rd trailer is
/// thus optional on decode so a newer SDK keeps reading older daemons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaWire {
    /// Relay's `node_id`. Senders open `client.send` to this id +
    /// `MAILBOX_APP_ID` + `MAILBOX_PUT_ENDPOINT_ID`.
    pub relay_node_id: [u8; 32],
    /// Unix-seconds when the receiver's RendezvousAd expires.
    /// Senders should treat the entry as stale past this point.
    pub valid_until_unix: u64,
    /// Sealed FCM/APNs envelope for this specific relay's X25519 sk
    /// — sender attaches this to its `MailboxPutPayload` so the
    /// relay can wake the receiver. May be empty (receiver did not
    /// register push).
    pub push_envelope: Vec<u8>,
    /// receiver-signed mailbox capability
    /// token bytes pulled from the resolved RendezvousAd. Senders forward
    /// these in `MailboxPutPayload.capability_token`. Empty when the
    /// receiver did not mint a token (legacy senders / hybrid identities
    /// / pre-slice-2 daemons). Cap [`MAX_MAILBOX_CAPABILITY_TOKEN_BYTES`].
    pub capability_token: Vec<u8>,
    /// Sealed `WakeHmacKey` envelope (Epic 489.10 slice 2b) copied verbatim
    /// from the resolved `RendezvousAd.wake_hmac_envelope`. Senders forward it
    /// in `MailboxPutPayload.wake_hmac_envelope` so the relay can mint a
    /// receiver-verifiable HMAC tag when dispatching the wake push. Empty when
    /// the receiver did not register for wake-HMAC (legacy receivers /
    /// pre-slice-2b daemons that emit only the first two trailers). Cap
    /// [`MAX_WAKE_HMAC_ENVELOPE_BYTES`].
    pub wake_hmac_envelope: Vec<u8>,
    /// KEM algorithm tag for [`Self::rendezvous_kem_pk`] (`0` = X25519).
    pub rendezvous_kem_algo: u8,
    /// The relay's KEM public key from the resolved v5 `RendezvousAd` — the
    /// seal target a sender uses to anonymously deposit a `MailboxPut` at this
    /// relay. Empty for pre-v5 ads / no relay key. 4th (optional) trailer; a
    /// pre-v5 daemon emits only the first three, so decode defaults to empty.
    /// Cap [`MAX_RENDEZVOUS_KEM_PK_BYTES`].
    pub rendezvous_kem_pk: Vec<u8>,
}

impl ReplicaWire {
    /// Per-entry header size before the envelope.
    pub const HEADER_SIZE: usize = 32 + 8 + 2;

    fn encode_to(&self, buf: &mut Vec<u8>) {
        debug_assert!(self.push_envelope.len() <= MAX_PUSH_ENVELOPE_BYTES);
        debug_assert!(self.capability_token.len() <= MAX_MAILBOX_CAPABILITY_TOKEN_BYTES);
        debug_assert!(self.wake_hmac_envelope.len() <= MAX_WAKE_HMAC_ENVELOPE_BYTES);
        buf.extend_from_slice(&self.relay_node_id);
        buf.extend_from_slice(&self.valid_until_unix.to_be_bytes());
        buf.extend_from_slice(&(self.push_envelope.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.push_envelope);
        // trailer.
        buf.extend_from_slice(&(self.capability_token.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.capability_token);
        // 3rd trailer (Epic 489.10 slice 2b): wake-HMAC envelope.
        buf.extend_from_slice(&(self.wake_hmac_envelope.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.wake_hmac_envelope);
        // 4th trailer (v5): relay KEM key — algo byte + length-prefixed pubkey.
        debug_assert!(self.rendezvous_kem_pk.len() <= MAX_RENDEZVOUS_KEM_PK_BYTES);
        buf.push(self.rendezvous_kem_algo);
        buf.extend_from_slice(&(self.rendezvous_kem_pk.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.rendezvous_kem_pk);
    }

    fn decode_from(buf: &[u8], offset: usize) -> Result<(Self, usize), ProtoError> {
        if buf.len() < offset + Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: offset + Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let relay_node_id = super::read_array::<32>(buf, offset)?;
        let valid_until_unix = super::read_u64_be(buf, offset + 32)?;
        let env_len = super::read_u16_be(buf, offset + 40)? as usize;
        if env_len > MAX_PUSH_ENVELOPE_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "replica_wire.envelope_len",
                value: env_len as u64,
                max: MAX_PUSH_ENVELOPE_BYTES as u64,
            });
        }
        let env_start = offset + Self::HEADER_SIZE;
        let env_end = env_start.checked_add(env_len).ok_or(ProtoError::Malformed(
            "replica_wire: env_len overflow".to_owned(),
        ))?;
        if buf.len() < env_end {
            return Err(ProtoError::BufferTooShort {
                need: env_end,
                got: buf.len(),
            });
        }
        let push_envelope = buf[env_start..env_end].to_vec();
        // mandatory trailer. The ReplicaWire
        // wire format ships only between local IPC peers (daemon ↔ SDK
        // on the same host), where version skew is operator-controlled
        // — they upgrade together as a package. So we require the
        // cap_token_len u16 unconditionally; old senders won't be
        // decoded by a new receiver and vice-versa, and that's fine for
        // local IPC. (Compare with MailboxPutPayload's optional trailer
        // approach where senders and relays can run mismatched versions
        // across the network.)
        if buf.len() < env_end + 2 {
            return Err(ProtoError::BufferTooShort {
                need: env_end + 2,
                got: buf.len(),
            });
        }
        let cap_len = super::read_u16_be(buf, env_end)? as usize;
        if cap_len > MAX_MAILBOX_CAPABILITY_TOKEN_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "replica_wire.cap_token_len",
                value: cap_len as u64,
                max: MAX_MAILBOX_CAPABILITY_TOKEN_BYTES as u64,
            });
        }
        let cap_start = env_end + 2;
        let cap_end = cap_start + cap_len;
        if buf.len() < cap_end {
            return Err(ProtoError::BufferTooShort {
                need: cap_end,
                got: buf.len(),
            });
        }
        let capability_token = buf[cap_start..cap_end].to_vec();
        // 3rd trailer (Epic 489.10 slice 2b): wake-HMAC envelope. Unlike the
        // cap_token trailer above, this one is OPTIONAL on decode so a newer
        // SDK keeps reading entries from a pre-slice-2b daemon that emits only
        // the first two trailers. If no bytes remain after cap_token (older
        // encoder), default `wake_hmac_envelope = vec![]` and report the
        // consumed length as `cap_end` so the multi-replica container walks to
        // the next entry boundary correctly.
        if buf.len() < cap_end + 2 {
            return Ok((
                Self {
                    relay_node_id,
                    valid_until_unix,
                    push_envelope,
                    capability_token,
                    wake_hmac_envelope: Vec::new(),
                    rendezvous_kem_algo: 0,
                    rendezvous_kem_pk: Vec::new(),
                },
                cap_end,
            ));
        }
        let wake_len = super::read_u16_be(buf, cap_end)? as usize;
        if wake_len > MAX_WAKE_HMAC_ENVELOPE_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "replica_wire.wake_hmac_envelope_len",
                value: wake_len as u64,
                max: MAX_WAKE_HMAC_ENVELOPE_BYTES as u64,
            });
        }
        let wake_start = cap_end + 2;
        let wake_end = wake_start + wake_len;
        if buf.len() < wake_end {
            return Err(ProtoError::BufferTooShort {
                need: wake_end,
                got: buf.len(),
            });
        }
        let wake_hmac_envelope = buf[wake_start..wake_end].to_vec();
        // 4th trailer (v5): OPTIONAL relay KEM key (algo byte + len-prefixed
        // pubkey). A pre-v5 daemon emits only the first three trailers — if
        // fewer than 3 bytes (algo + u16 len) remain, default to "no key" and
        // report `wake_end` as the consumed length so the container walks to
        // the next entry boundary correctly.
        if buf.len() < wake_end + 3 {
            return Ok((
                Self {
                    relay_node_id,
                    valid_until_unix,
                    push_envelope,
                    capability_token,
                    wake_hmac_envelope,
                    rendezvous_kem_algo: 0,
                    rendezvous_kem_pk: Vec::new(),
                },
                wake_end,
            ));
        }
        let rendezvous_kem_algo = buf[wake_end];
        let kem_len = super::read_u16_be(buf, wake_end + 1)? as usize;
        if kem_len > MAX_RENDEZVOUS_KEM_PK_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "replica_wire.rendezvous_kem_pk_len",
                value: kem_len as u64,
                max: MAX_RENDEZVOUS_KEM_PK_BYTES as u64,
            });
        }
        let kem_start = wake_end + 3;
        let kem_end = kem_start + kem_len;
        if buf.len() < kem_end {
            return Err(ProtoError::BufferTooShort {
                need: kem_end,
                got: buf.len(),
            });
        }
        let rendezvous_kem_pk = buf[kem_start..kem_end].to_vec();
        Ok((
            Self {
                relay_node_id,
                valid_until_unix,
                push_envelope,
                capability_token,
                wake_hmac_envelope,
                rendezvous_kem_algo,
                rendezvous_kem_pk,
            },
            kem_end,
        ))
    }
}

/// Payload [`crate::family::LocalAppMsg::LookupRendezvousReplicasResp`].
///
/// Wire layout: `[count_u8 | ReplicaWire * count]`.
///
/// Empty `entries` = "no rendezvous publication found" or "all returned
/// ads were unverifiable" — caller cannot distinguish; either way it
/// should fall back to direct delivery / peer-sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupRendezvousReplicasRespPayload {
    /// Verified replica entries; up to `min(MAX_RENDEZVOUS_REPLICAS, request.max_replicas)`.
    pub entries: Vec<ReplicaWire>,
}

impl LookupRendezvousReplicasRespPayload {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.entries.len() <= MAX_RENDEZVOUS_REPLICAS);
        let mut buf = Vec::with_capacity(1 + self.entries.len() * ReplicaWire::HEADER_SIZE);
        buf.push(self.entries.len() as u8);
        for e in &self.entries {
            e.encode_to(&mut buf);
        }
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.is_empty() {
            return Err(ProtoError::BufferTooShort { need: 1, got: 0 });
        }
        let count = buf[0] as usize;
        if count > MAX_RENDEZVOUS_REPLICAS {
            return Err(ProtoError::ValueTooLarge {
                field: "lookup_rendezvous_replicas_resp.count",
                value: count as u64,
                max: MAX_RENDEZVOUS_REPLICAS as u64,
            });
        }
        let mut entries = Vec::with_capacity(count);
        let mut offset = 1;
        for _ in 0..count {
            let (e, next) = ReplicaWire::decode_from(buf, offset)?;
            entries.push(e);
            offset = next;
        }
        Ok(Self { entries })
    }
}

/// Payload [`crate::family::LocalAppMsg::SetMobileBackgroundMode`].
///
/// Wire layout:
/// ```text
/// [0] mode u8 (0=Foreground, 1=Active, 2=LowPower)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetMobileBackgroundModePayload {
    /// Background mode to switch to.
    pub mode: MobileBackgroundMode,
}

impl SetMobileBackgroundModePayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 1;

    /// Encode to the fixed 1-byte layout.
    pub fn encode(&self) -> Vec<u8> {
        vec![self.mode.to_wire()]
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.is_empty() {
            return Err(ProtoError::BufferTooShort { need: 1, got: 0 });
        }
        Ok(Self {
            mode: MobileBackgroundMode::from_wire(buf[0])?,
        })
    }
}

/// Coarse classification of the local network attachment.
///
/// Wire byte:
/// `0` = Offline (no data link — daemon should pause reconnect storms)
/// `1` = Wifi (typical home / office / public Wi-Fi)
/// `2` = Cellular (3G / LTE / 5G — likely CGN, expect different egress)
/// `3` = Ethernet (cabled link — typically stable, no metering)
/// `255` = Unknown (best-effort caller didn't classify)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetworkKind {
    /// No usable network.
    Offline = 0,
    /// Wi-Fi association.
    Wifi = 1,
    /// Cellular (3G / LTE / 5G).
    Cellular = 2,
    /// Wired ethernet.
    Ethernet = 3,
    /// Best-effort fallback.
    Unknown = 255,
}

impl NetworkKind {
    /// Decode from wire byte.
    pub fn from_wire(b: u8) -> Self {
        match b {
            0 => Self::Offline,
            1 => Self::Wifi,
            2 => Self::Cellular,
            3 => Self::Ethernet,
            _ => Self::Unknown,
        }
    }

    /// Wire byte representation.
    pub fn to_wire(self) -> u8 {
        self as u8
    }
}

/// Payload [`crate::family::LocalAppMsg::NetworkChanged`].
///
/// Wire layout:
/// ```text
/// [0] kind u8 (NetworkKind wire byte)
/// [1..3] mtu_hint u16 BE (0 = unknown / use default)
/// [3..7] reserved u32 BE (must be 0 — future flags)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkChangedPayload {
    /// Coarse network kind. Daemon uses this to decide whether to
    /// proactively tear down sessions (e.g. on Wi-Fi → Cellular flips
    /// the public-egress IP changes, so warm sessions are doomed).
    pub kind: NetworkKind,
    /// Hint about path MTU — 0 means "use default" (1280 for IPv6
    /// or per-transport default). Useful for cellular networks that
    /// often have unusual MTUs.
    pub mtu_hint: u16,
}

impl NetworkChangedPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 1 + 2 + 4;

    /// Encode to the fixed 7-byte layout.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.push(self.kind.to_wire());
        buf.extend_from_slice(&self.mtu_hint.to_be_bytes());
        buf.extend_from_slice(&[0u8; 4]); // reserved
        buf
    }

    /// Decode from wire bytes. Reserved bytes are ignored on read so
    /// that older daemons stay compatible with future flag additions.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let kind = NetworkKind::from_wire(buf[0]);
        let mtu_hint = u16::from_be_bytes([buf[1], buf[2]]);
        Ok(Self { kind, mtu_hint })
    }
}

// ── Node-identity query ────────────────────────────────────────

/// Maximum public-key bytes carried in `NodeIdentityPayload`. Chosen to fit
/// Falcon-512 (897 B) + slack for future PQ algos with larger keys.
pub const MAX_NODE_IDENTITY_PUBKEY_LEN: usize = 1536;

/// Payload [`crate::family::LocalAppMsg::NodeIdentity`].
///
/// Carries the daemon's own identity to a connected IPC client so the app
/// can display the user's address ("you are: 0xABC…") and use the node_id
/// in routing decisions without a separate admin-socket round-trip.
///
/// Wire layout:
/// ```text
/// [0..32] node_id [u8; 32]
/// [32] algo u8 (veil_types::SignatureAlgorithm wire byte)
/// [33..35] pubkey_len u16 BE
/// [35..35+pubkey_len] public_key bytes (raw signing pubkey for `algo`)
///
/// // Optional trailer:
/// [N] relay_x25519_present u8 (0 = absent, 1 = present)
/// [N+1..N+33] relay_x25519_pubkey [u8; 32] (only if present == 1)
/// ```
///
/// **Backward compatibility:** the relay-X25519 trailer is optional.
/// Old clients that read only up to `35 + pubkey_len` see the same
/// payload as before. Old daemons that don't append the trailer
/// produce a buffer that decodes to `relay_x25519_pubkey = None` on a
/// new client. This means the field can be added without bumping
/// `IPC_PROTOCOL_VERSION`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentityPayload {
    /// Daemon's `node_id = BLAKE3(public_key)` — 32 bytes.
    pub node_id: [u8; 32],
    /// Signature-algorithm wire byte (matches `veil_types::SignatureAlgorithm::wire_byte`).
    pub algo: u8,
    /// Raw signing public key for `algo`. Length depends on algo:
    /// Ed25519 = 32 B, Falcon-512 ≈ 897 B. Hard-capped at
    /// [`MAX_NODE_IDENTITY_PUBKEY_LEN`].
    pub public_key: Vec<u8>,
    /// Optional X25519 public key the daemon uses as a relay-side seal
    /// target for push-envelopes. Apps that want
    /// to seal a push-token for this relay use this exact key with
    /// [`veil-anonymity::push_envelope::seal_push_envelope`].
    /// `None` means the daemon is not relay-capable (no X25519 sk
    /// configured) — apps must pick a different relay.
    pub relay_x25519_pubkey: Option<[u8; 32]>,
}

impl NodeIdentityPayload {
    const FIXED_SIZE: usize = 32 + 1 + 2;

    /// Encode to wire bytes. Caller is responsible for the
    /// `public_key` length staying ≤ [`MAX_NODE_IDENTITY_PUBKEY_LEN`].
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.public_key.len() <= MAX_NODE_IDENTITY_PUBKEY_LEN,
            "public_key exceeds MAX_NODE_IDENTITY_PUBKEY_LEN"
        );
        debug_assert!(
            self.public_key.len() <= u16::MAX as usize,
            "public_key length must fit in u16"
        );
        let trailer = if self.relay_x25519_pubkey.is_some() {
            1 + 32
        } else {
            1
        };
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + self.public_key.len() + trailer);
        buf.extend_from_slice(&self.node_id);
        buf.push(self.algo);
        buf.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.public_key);
        match self.relay_x25519_pubkey {
            Some(pk) => {
                buf.push(1);
                buf.extend_from_slice(&pk);
            }
            None => buf.push(0),
        }
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let node_id = super::read_array::<32>(buf, 0)?;
        let algo = buf[32];
        let pubkey_len = super::read_u16_be(buf, 33)? as usize;
        if pubkey_len > MAX_NODE_IDENTITY_PUBKEY_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "node_identity.public_key_len",
                value: pubkey_len as u64,
                max: MAX_NODE_IDENTITY_PUBKEY_LEN as u64,
            });
        }
        let total = Self::FIXED_SIZE + pubkey_len;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        // Optional trailer. Old daemons stop at `total`; new daemons
        // append at least one flag byte (0 or 1).
        let relay_x25519_pubkey = if buf.len() > total {
            match buf[total] {
                0 => None,
                1 => {
                    let need = total + 1 + 32;
                    if buf.len() < need {
                        return Err(ProtoError::BufferTooShort {
                            need,
                            got: buf.len(),
                        });
                    }
                    Some(super::read_array::<32>(buf, total + 1)?)
                }
                other => {
                    return Err(ProtoError::ValueTooLarge {
                        field: "node_identity.relay_x25519_present",
                        value: other as u64,
                        max: 1,
                    });
                }
            }
        } else {
            None
        };
        Ok(Self {
            node_id,
            algo,
            public_key: buf[Self::FIXED_SIZE..total].to_vec(),
            relay_x25519_pubkey,
        })
    }
}

// ── Peer-list query ────────────────────────────────────────────

/// Hard cap on peers carried in `PeersListPayload`. Bounded so a daemon
/// with many active sessions can't accidentally exceed the IPC frame
/// size limit (`MAX_FRAME_BODY_BYTES`). At 256 entries × ~100 B per
/// entry ≈ 25 KiB which fits comfortably in the IPC frame budget.
pub const MAX_PEERS_LIST_ENTRIES: usize = 256;

/// Hard cap on transport-URI length per entry. 4 KiB tolerates Falcon-
/// style long URIs (tls-cert-pinned + SNI hints) while preventing a
/// pathological config from blowing the frame budget.
pub const MAX_PEER_TRANSPORT_LEN: usize = 4096;

/// Session-state wire byte [`PeersListEntry::state`].
pub mod peer_state {
    /// Session is currently in handshake / not yet ready for traffic.
    pub const CONNECTING: u8 = 0;
    /// Session is active and exchanging frames.
    pub const ACTIVE: u8 = 1;
    /// Session is closing or has been closed.
    pub const CLOSED: u8 = 2;
    /// State unknown / could not be classified.
    pub const UNKNOWN: u8 = 255;
}

/// Direction wire byte [`PeersListEntry::direction`].
pub mod peer_direction {
    /// Peer connected to us (server side).
    pub const INBOUND: u8 = 0;
    /// We dialed the peer (client side).
    pub const OUTBOUND: u8 = 1;
}

/// One entry [`PeersListPayload`].
///
/// Wire layout:
/// ```text
/// [0..32] node_id [u8; 32]
/// [32] state u8 (peer_state::*)
/// [33] direction u8 (peer_direction::*)
/// [34..36] transport_len u16 BE
/// [36..36+t_len] transport bytes (UTF-8 transport URI)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeersListEntry {
    /// Peer's `node_id` (32 bytes, derived from peer's signing pubkey).
    pub node_id: [u8; 32],
    /// Session state (see [`peer_state`]).
    pub state: u8,
    /// Connection direction (see [`peer_direction`]).
    pub direction: u8,
    /// Transport URI (e.g. `tcp://1.2.3.4:5555`). May be empty if the
    /// peer was matched without a known transport (rare).
    pub transport: Vec<u8>,
}

impl PeersListEntry {
    /// Fixed wire-prefix size before the variable transport bytes.
    pub const FIXED_SIZE: usize = 32 + 1 + 1 + 2;

    /// Encode to wire bytes.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        debug_assert!(
            self.transport.len() <= MAX_PEER_TRANSPORT_LEN,
            "transport exceeds MAX_PEER_TRANSPORT_LEN"
        );
        debug_assert!(
            self.transport.len() <= u16::MAX as usize,
            "transport length must fit in u16"
        );
        buf.extend_from_slice(&self.node_id);
        buf.push(self.state);
        buf.push(self.direction);
        buf.extend_from_slice(&(self.transport.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.transport);
    }

    /// Decode one entry, returning `(entry, bytes_consumed)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let node_id = super::read_array::<32>(buf, 0)?;
        let state = buf[32];
        let direction = buf[33];
        let t_len = super::read_u16_be(buf, 34)? as usize;
        if t_len > MAX_PEER_TRANSPORT_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "peer_entry.transport_len",
                value: t_len as u64,
                max: MAX_PEER_TRANSPORT_LEN as u64,
            });
        }
        let total = Self::FIXED_SIZE + t_len;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok((
            Self {
                node_id,
                state,
                direction,
                transport: buf[Self::FIXED_SIZE..total].to_vec(),
            },
            total,
        ))
    }
}

/// Payload [`crate::family::LocalAppMsg::PeersList`].
///
/// Wire layout:
/// ```text
/// [0..2] count u16 BE (number of entries; ≤ MAX_PEERS_LIST_ENTRIES)
/// [2..] entries sequence [`PeersListEntry`]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeersListPayload {
    /// Active peer entries. Server side trims to `MAX_PEERS_LIST_ENTRIES`
    /// before encoding so a daemon with thousands of sessions doesn't
    /// overflow the IPC frame body budget; clients should treat this
    /// as a snapshot (not exhaustive) on heavily-loaded relays.
    pub peers: Vec<PeersListEntry>,
}

impl PeersListPayload {
    /// Encode to wire bytes. Caller is responsible for ensuring
    /// `peers.len <= MAX_PEERS_LIST_ENTRIES`.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.peers.len() <= MAX_PEERS_LIST_ENTRIES,
            "peers exceeds MAX_PEERS_LIST_ENTRIES"
        );
        debug_assert!(
            self.peers.len() <= u16::MAX as usize,
            "peers count must fit in u16"
        );
        let mut buf = Vec::with_capacity(
            2 + self
                .peers
                .iter()
                .map(|p| PeersListEntry::FIXED_SIZE + p.transport.len())
                .sum::<usize>(),
        );
        buf.extend_from_slice(&(self.peers.len() as u16).to_be_bytes());
        for entry in &self.peers {
            entry.encode_into(&mut buf);
        }
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 2 {
            return Err(ProtoError::BufferTooShort {
                need: 2,
                got: buf.len(),
            });
        }
        let count = super::read_u16_be(buf, 0)? as usize;
        if count > MAX_PEERS_LIST_ENTRIES {
            return Err(ProtoError::ValueTooLarge {
                field: "peers_list.count",
                value: count as u64,
                max: MAX_PEERS_LIST_ENTRIES as u64,
            });
        }
        let mut peers = Vec::with_capacity(count);
        let mut offset = 2;
        for _ in 0..count {
            if offset > buf.len() {
                return Err(ProtoError::BufferTooShort {
                    need: offset,
                    got: buf.len(),
                });
            }
            let (entry, consumed) = PeersListEntry::decode(&buf[offset..])?;
            offset += consumed;
            peers.push(entry);
        }
        Ok(Self { peers })
    }
}

// ── Bootstrap-URI join ─────────────────────────────────────────

/// Hard cap on URI byte length carried in `JoinBootstrapPayload`.
/// 8 KiB matches `MAX_SIGNED_INVITE_BYTES` in veil-bootstrap (longest
/// legitimate URI variant — Falcon-512 signed envelope). Anything
/// beyond this is rejected pre-decode to defend against pathological
/// app input.
pub const MAX_JOIN_URI_LEN: usize = 8192;

/// Hard cap on password byte length for encrypted-invite URIs.
/// 1 KiB tolerates extremely long passphrases without giving an
/// attacker an unbounded allocation oracle.
pub const MAX_JOIN_PASSWORD_LEN: usize = 1024;

/// Hard cap on expected-issuer-pubkey bytes for signed-invite URIs.
/// 1 KiB matches Falcon-512 raw pubkey + base64 expansion overhead.
pub const MAX_JOIN_ISSUER_PK_LEN: usize = 1024;

/// Hard cap on detail bytes in `JoinBootstrapResultPayload`. Daemon-
/// composed human-readable error messages — keep small so a
/// pathological error path can't pin a large allocation.
pub const MAX_JOIN_DETAIL_LEN: usize = 1024;

/// Result codes for [`JoinBootstrapResultPayload::status`].
pub mod join_status {
    /// Peer was decoded, verified, and registered — outbound dial in flight.
    pub const OK: u8 = 0;
    /// URI parse failed (bad scheme, malformed base64, truncated body).
    pub const INVALID_URI: u8 = 1;
    /// URI is encrypted (`veil:pair?…`) but no password was provided.
    pub const PASSWORD_REQUIRED: u8 = 2;
    /// URI is encrypted and the provided password was wrong.
    pub const PASSWORD_WRONG: u8 = 3;
    /// URI is signed (`veil:signed-invite?…`) and the signature did not verify
    /// against `expected_issuer_pk` (or expected_issuer_pk was omitted entirely
    /// — daemon refuses to register without an external trust signal).
    pub const SIGNATURE_INVALID: u8 = 4;
    /// Daemon-side error registering the peer (out of memory, runtime
    /// in shutdown, etc.). See `detail` field.
    pub const INTERNAL_ERROR: u8 = 5;
    /// Same `pubkey` is already in the runtime peer-set — no-op success.
    pub const ALREADY_REGISTERED: u8 = 6;
}

/// Payload [`crate::family::LocalAppMsg::JoinBootstrapUri`].
///
/// Wire layout:
/// ```text
/// [0..2] uri_len u16 BE (≤ MAX_JOIN_URI_LEN)
/// [2..2+uri_len] uri UTF-8 bytes
/// [..] password_len u16 BE (≤ MAX_JOIN_PASSWORD_LEN; 0 = absent)
/// [..] password UTF-8 bytes
/// [..] issuer_pk_len u16 BE (≤ MAX_JOIN_ISSUER_PK_LEN; 0 = absent)
/// [..] issuer_pk UTF-8 bytes (base64 pubkey)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinBootstrapPayload {
    /// Raw `veil:` URI (plain / encrypted / signed-invite — daemon
    /// dispatches by scheme prefix).
    pub uri: String,
    /// Password for `veil:pair?…` envelopes; `None` for plain /
    /// signed URIs. Wire-mismatch (password sent when URI is plain)
    /// is rejected by the daemon with status `INVALID_URI`.
    pub password: Option<String>,
    /// Base64-encoded expected issuer pubkey for `veil:signed-invite?…`
    /// envelopes; `None` for plain / encrypted URIs. REQUIRED when
    /// URI is signed — daemon refuses to register without an external
    /// trust signal (anyone could sign an envelope claiming to be
    /// anyone — the signature is only useful when verified against
    /// an OOB-known pubkey).
    pub expected_issuer_pk: Option<String>,
}

impl JoinBootstrapPayload {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.uri.len() <= MAX_JOIN_URI_LEN,
            "uri exceeds MAX_JOIN_URI_LEN"
        );
        let pw_len = self.password.as_ref().map(|s| s.len()).unwrap_or(0);
        let pk_len = self
            .expected_issuer_pk
            .as_ref()
            .map(|s| s.len())
            .unwrap_or(0);
        debug_assert!(
            pw_len <= MAX_JOIN_PASSWORD_LEN,
            "password exceeds MAX_JOIN_PASSWORD_LEN"
        );
        debug_assert!(
            pk_len <= MAX_JOIN_ISSUER_PK_LEN,
            "issuer_pk exceeds MAX_JOIN_ISSUER_PK_LEN"
        );
        let mut buf = Vec::with_capacity(2 + self.uri.len() + 2 + pw_len + 2 + pk_len);
        buf.extend_from_slice(&(self.uri.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.uri.as_bytes());
        buf.extend_from_slice(&(pw_len as u16).to_be_bytes());
        if let Some(pw) = &self.password {
            buf.extend_from_slice(pw.as_bytes());
        }
        buf.extend_from_slice(&(pk_len as u16).to_be_bytes());
        if let Some(pk) = &self.expected_issuer_pk {
            buf.extend_from_slice(pk.as_bytes());
        }
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 2 {
            return Err(ProtoError::BufferTooShort {
                need: 2,
                got: buf.len(),
            });
        }
        let uri_len = super::read_u16_be(buf, 0)? as usize;
        if uri_len > MAX_JOIN_URI_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "join_bootstrap.uri_len",
                value: uri_len as u64,
                max: MAX_JOIN_URI_LEN as u64,
            });
        }
        let uri_end = 2 + uri_len;
        if buf.len() < uri_end + 2 {
            return Err(ProtoError::BufferTooShort {
                need: uri_end + 2,
                got: buf.len(),
            });
        }
        let uri = std::str::from_utf8(&buf[2..uri_end])
            .map_err(|_| ProtoError::InvalidUtf8)?
            .to_string();
        let pw_len = super::read_u16_be(buf, uri_end)? as usize;
        if pw_len > MAX_JOIN_PASSWORD_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "join_bootstrap.password_len",
                value: pw_len as u64,
                max: MAX_JOIN_PASSWORD_LEN as u64,
            });
        }
        let pw_end = uri_end + 2 + pw_len;
        if buf.len() < pw_end + 2 {
            return Err(ProtoError::BufferTooShort {
                need: pw_end + 2,
                got: buf.len(),
            });
        }
        let password = if pw_len == 0 {
            None
        } else {
            Some(
                std::str::from_utf8(&buf[uri_end + 2..pw_end])
                    .map_err(|_| ProtoError::InvalidUtf8)?
                    .to_string(),
            )
        };
        let pk_len = super::read_u16_be(buf, pw_end)? as usize;
        if pk_len > MAX_JOIN_ISSUER_PK_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "join_bootstrap.issuer_pk_len",
                value: pk_len as u64,
                max: MAX_JOIN_ISSUER_PK_LEN as u64,
            });
        }
        let pk_end = pw_end + 2 + pk_len;
        if buf.len() < pk_end {
            return Err(ProtoError::BufferTooShort {
                need: pk_end,
                got: buf.len(),
            });
        }
        let expected_issuer_pk = if pk_len == 0 {
            None
        } else {
            Some(
                std::str::from_utf8(&buf[pw_end + 2..pk_end])
                    .map_err(|_| ProtoError::InvalidUtf8)?
                    .to_string(),
            )
        };
        Ok(Self {
            uri,
            password,
            expected_issuer_pk,
        })
    }
}

/// Payload [`crate::family::LocalAppMsg::JoinBootstrapResult`].
///
/// Wire layout:
/// ```text
/// [0] status u8 (join_status::*)
/// [1..33] peer_node_id [u8; 32] (zero-filled when status!= OK)
/// [33..35] detail_len u16 BE
/// [35..] detail UTF-8 bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinBootstrapResultPayload {
    /// Status code (see [`join_status`]).
    pub status: u8,
    /// Decoded peer's `node_id` on success / `ALREADY_REGISTERED`;
    /// zero-filled otherwise. Caller should only consult this on
    /// `status == OK || status == ALREADY_REGISTERED`.
    pub peer_node_id: [u8; 32],
    /// Optional human-readable detail (UTF-8). Bounded to
    /// [`MAX_JOIN_DETAIL_LEN`] by the daemon.
    pub detail: Vec<u8>,
}

impl JoinBootstrapResultPayload {
    const FIXED_SIZE: usize = 1 + 32 + 2;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.detail.len() <= MAX_JOIN_DETAIL_LEN,
            "detail exceeds MAX_JOIN_DETAIL_LEN"
        );
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + self.detail.len());
        buf.push(self.status);
        buf.extend_from_slice(&self.peer_node_id);
        buf.extend_from_slice(&(self.detail.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.detail);
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let status = buf[0];
        let peer_node_id = super::read_array::<32>(buf, 1)?;
        let detail_len = super::read_u16_be(buf, 33)? as usize;
        if detail_len > MAX_JOIN_DETAIL_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "join_result.detail_len",
                value: detail_len as u64,
                max: MAX_JOIN_DETAIL_LEN as u64,
            });
        }
        let total = Self::FIXED_SIZE + detail_len;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            status,
            peer_node_id,
            detail: buf[Self::FIXED_SIZE..total].to_vec(),
        })
    }
}

// ── Create bootstrap invite ────────────────────────────────────

/// Max raw URI length emitted by [`CreateBootstrapInviteResultPayload`].
/// Same cap as the consume side ([`MAX_JOIN_URI_LEN`]) so encode → decode
/// round-trips fit cleanly.
pub const MAX_CREATE_INVITE_URI_LEN: usize = MAX_JOIN_URI_LEN;

/// Max password length (UTF-8 bytes) on [`CreateBootstrapInvitePayload`].
/// Same cap as the consume side.
pub const MAX_CREATE_INVITE_PASSWORD_LEN: usize = MAX_JOIN_PASSWORD_LEN;

/// Hard cap on detail bytes in [`CreateBootstrapInviteResultPayload`].
pub const MAX_CREATE_INVITE_DETAIL_LEN: usize = MAX_JOIN_DETAIL_LEN;

/// Result codes for [`CreateBootstrapInviteResultPayload::status`].
pub mod create_invite_status {
    /// Invite was assembled and encoded successfully.  URI field is
    /// populated, detail is empty.
    pub const OK: u8 = 0;
    /// Daemon's config has no `[identity]` or no `[[listen]]` entry —
    /// invite has no peer to advertise.  Detail names which.
    pub const NOT_CONFIGURED: u8 = 1;
    /// Caller-supplied password was rejected (empty after trim or
    /// exceeds [`MAX_CREATE_INVITE_PASSWORD_LEN`]).
    pub const BAD_PASSWORD: u8 = 2;
    /// Daemon-internal failure (encode error, runtime in shutdown,
    /// hybrid-identity not supported on encrypted path, …).  Detail
    /// carries human-readable reason.
    pub const INTERNAL_ERROR: u8 = 3;
}

/// Payload [`crate::family::LocalAppMsg::CreateBootstrapInvite`].
///
/// Wire layout:
/// ```text
/// [0..2] password_len u16 BE (≤ MAX_CREATE_INVITE_PASSWORD_LEN; 0 = absent → plain invite)
/// [2..2+pw_len] password UTF-8 bytes
/// ```
///
/// `password = None` emits a plain `veil:bootstrap?…` URI; `Some(...)`
/// emits an `veil:pair?…` encrypted envelope (Argon2id-derived KEK +
/// AEAD).  Signed variant (`veil:signed-invite?…`) is a future slice —
/// requires plumbing the daemon's signing key through the IPC sink trait.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateBootstrapInvitePayload {
    /// Encryption passphrase for the encrypted envelope variant.
    /// `None` ⇒ plain `veil:bootstrap?…` URI (most common, fastest
    /// QR render).  `Some(pw)` ⇒ encrypted invite — receiver MUST
    /// supply the same passphrase on consume.
    pub password: Option<String>,
}

impl CreateBootstrapInvitePayload {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let pw_len = self.password.as_ref().map(|s| s.len()).unwrap_or(0);
        debug_assert!(
            pw_len <= MAX_CREATE_INVITE_PASSWORD_LEN,
            "password exceeds MAX_CREATE_INVITE_PASSWORD_LEN"
        );
        let mut buf = Vec::with_capacity(2 + pw_len);
        buf.extend_from_slice(&(pw_len as u16).to_be_bytes());
        if let Some(pw) = &self.password {
            buf.extend_from_slice(pw.as_bytes());
        }
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 2 {
            return Err(ProtoError::BufferTooShort {
                need: 2,
                got: buf.len(),
            });
        }
        let pw_len = super::read_u16_be(buf, 0)? as usize;
        if pw_len > MAX_CREATE_INVITE_PASSWORD_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "create_invite.password_len",
                value: pw_len as u64,
                max: MAX_CREATE_INVITE_PASSWORD_LEN as u64,
            });
        }
        if buf.len() < 2 + pw_len {
            return Err(ProtoError::BufferTooShort {
                need: 2 + pw_len,
                got: buf.len(),
            });
        }
        let password = if pw_len == 0 {
            None
        } else {
            Some(
                std::str::from_utf8(&buf[2..2 + pw_len])
                    .map_err(|_| ProtoError::InvalidUtf8)?
                    .to_string(),
            )
        };
        Ok(Self { password })
    }
}

/// Payload [`crate::family::LocalAppMsg::CreateBootstrapInviteResult`].
///
/// Wire layout:
/// ```text
/// [0] status u8 (create_invite_status::*)
/// [1..3] uri_len u16 BE (≤ MAX_CREATE_INVITE_URI_LEN; 0 on non-OK)
/// [3..3+uri_len] uri UTF-8 bytes
/// [3+uri_len..3+uri_len+2] detail_len u16 BE (≤ MAX_CREATE_INVITE_DETAIL_LEN)
/// [3+uri_len+2..] detail UTF-8 bytes
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateBootstrapInviteResultPayload {
    /// Status code (see [`create_invite_status`]).
    pub status: u8,
    /// Encoded invite URI on success; empty otherwise.
    pub uri: String,
    /// Human-readable detail (UTF-8); typically empty on success.
    pub detail: Vec<u8>,
}

impl CreateBootstrapInviteResultPayload {
    const FIXED_HEAD: usize = 1 + 2;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.uri.len() <= MAX_CREATE_INVITE_URI_LEN,
            "uri exceeds MAX_CREATE_INVITE_URI_LEN"
        );
        debug_assert!(
            self.detail.len() <= MAX_CREATE_INVITE_DETAIL_LEN,
            "detail exceeds MAX_CREATE_INVITE_DETAIL_LEN"
        );
        let mut buf = Vec::with_capacity(Self::FIXED_HEAD + self.uri.len() + 2 + self.detail.len());
        buf.push(self.status);
        buf.extend_from_slice(&(self.uri.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.uri.as_bytes());
        buf.extend_from_slice(&(self.detail.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.detail);
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_HEAD {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_HEAD,
                got: buf.len(),
            });
        }
        let status = buf[0];
        let uri_len = super::read_u16_be(buf, 1)? as usize;
        if uri_len > MAX_CREATE_INVITE_URI_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "create_invite_result.uri_len",
                value: uri_len as u64,
                max: MAX_CREATE_INVITE_URI_LEN as u64,
            });
        }
        let uri_end = Self::FIXED_HEAD + uri_len;
        if buf.len() < uri_end + 2 {
            return Err(ProtoError::BufferTooShort {
                need: uri_end + 2,
                got: buf.len(),
            });
        }
        let uri = std::str::from_utf8(&buf[Self::FIXED_HEAD..uri_end])
            .map_err(|_| ProtoError::InvalidUtf8)?
            .to_string();
        let detail_len = super::read_u16_be(buf, uri_end)? as usize;
        if detail_len > MAX_CREATE_INVITE_DETAIL_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "create_invite_result.detail_len",
                value: detail_len as u64,
                max: MAX_CREATE_INVITE_DETAIL_LEN as u64,
            });
        }
        let total = uri_end + 2 + detail_len;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            status,
            uri,
            detail: buf[uri_end + 2..total].to_vec(),
        })
    }
}

// ── Multi-device pairing ceremony (Epic 489.8) ─────────────────

/// Max single-message payload cap for any pairing ceremony frame
/// (Hello / Cert / Confirm bytes flowing between Source and Target).
/// 64 KiB easily fits the largest IdentityDocument in the Cert frame
/// (`MAX_IDENTITY_DOCUMENT_BYTES` is currently 16 KiB) plus all wire
/// overhead.  Bounded so a sandboxed-but-IPC-capable adversary can't
/// pin gigabytes of allocation through this surface.
pub const MAX_PAIR_CEREMONY_BYTES: usize = 64 * 1024;

/// Max scanned URI length on the Target side.  Same cap as the
/// renderer applies (`veil_proto::pairing_invite::MAX_PAIR_URI_BYTES`).
pub const MAX_PAIR_URI_LEN: usize = 1024;

/// 6-digit OOB code length (always 6 ASCII digits).
pub const PAIR_OOB_CODE_LEN: usize = 6;

/// Detail bytes cap for error responses.
pub const MAX_PAIR_DETAIL_LEN: usize = 1024;

/// Result codes for [`PairSourceCreateInviteResultPayload::status`].
pub mod pair_source_status {
    /// Invite assembled.  URI field populated.
    pub const OK: u8 = 0;
    /// Daemon's config has no `[identity]` or no sovereign-identity
    /// master_sk on disk — ceremony cannot proceed.
    pub const NOT_CONFIGURED: u8 = 1;
    /// Source-side ceremony already in progress (one-at-a-time policy).
    /// Cancel the in-flight ceremony OR wait for its timeout.
    pub const ALREADY_IN_PROGRESS: u8 = 2;
    /// Daemon-internal failure (master_sk locked, encode error, …).
    pub const INTERNAL_ERROR: u8 = 3;
    /// `handle_hello` / `handle_confirm`: ceremony state not matches
    /// the expected step (no in-progress ceremony, or wrong-order op).
    pub const WRONG_STATE: u8 = 4;
    /// `handle_hello`: target's Hello payload failed MAC / pair_secret
    /// correlation.  Most common cause: the user scanned a stale QR
    /// from a previous (expired) ceremony.
    pub const BAD_HELLO: u8 = 5;
    /// `handle_confirm`: target reported user aborted (codes didn't
    /// match).  Caller MUST drop the in-progress IdentityKey.
    pub const USER_ABORTED: u8 = 6;
    /// `handle_confirm`: confirm proof failed verification
    /// (tampered / wrong session).
    pub const BAD_CONFIRM: u8 = 7;
}

/// Result codes for `PairTarget*ResultPayload::status`.
pub mod pair_target_status {
    /// Operation succeeded.
    pub const OK: u8 = 0;
    /// `consume_uri`: scanned URI failed parse / scheme check.
    pub const BAD_URI: u8 = 1;
    /// `consume_uri`: scanned URI is past its `expires_at_unix`.
    pub const EXPIRED: u8 = 2;
    /// Target-side ceremony already in progress.
    pub const ALREADY_IN_PROGRESS: u8 = 3;
    /// `handle_cert`: Cert bytes failed decode / sig verify / oob derive.
    pub const BAD_CERT: u8 = 4;
    /// State machine mismatch.
    pub const WRONG_STATE: u8 = 5;
    /// Daemon-internal failure (I/O on persist, encode error, …).
    pub const INTERNAL_ERROR: u8 = 6;
}

/// Payload [`crate::family::LocalAppMsg::PairSourceCreateInvite`].
///
/// Wire layout:
/// ```text
/// [0..2] master_password_len u16 BE (≤ MAX_PAIR_DETAIL_LEN; 0 = absent)
/// [2..2+pw_len] master_password UTF-8 bytes
/// ```
/// The password is needed when the sovereign identity's master_sk is
/// encrypted at rest (Argon2id master.enc); on success the daemon
/// derives master_sk, holds it for the ceremony, and drops at finalize
/// or timeout.  Empty password = "master_sk is unencrypted on disk".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairSourceCreateInvitePayload {
    pub master_password: Option<String>,
}

impl PairSourceCreateInvitePayload {
    pub fn encode(&self) -> Vec<u8> {
        let pw_len = self.master_password.as_ref().map(|s| s.len()).unwrap_or(0);
        let mut buf = Vec::with_capacity(2 + pw_len);
        buf.extend_from_slice(&(pw_len as u16).to_be_bytes());
        if let Some(pw) = &self.master_password {
            buf.extend_from_slice(pw.as_bytes());
        }
        buf
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 2 {
            return Err(ProtoError::BufferTooShort {
                need: 2,
                got: buf.len(),
            });
        }
        let pw_len = super::read_u16_be(buf, 0)? as usize;
        if pw_len > MAX_PAIR_DETAIL_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "pair_source_create.password_len",
                value: pw_len as u64,
                max: MAX_PAIR_DETAIL_LEN as u64,
            });
        }
        if buf.len() < 2 + pw_len {
            return Err(ProtoError::BufferTooShort {
                need: 2 + pw_len,
                got: buf.len(),
            });
        }
        let master_password = if pw_len == 0 {
            None
        } else {
            Some(
                std::str::from_utf8(&buf[2..2 + pw_len])
                    .map_err(|_| ProtoError::InvalidUtf8)?
                    .to_string(),
            )
        };
        Ok(Self { master_password })
    }
}

/// Payload [`crate::family::LocalAppMsg::PairSourceCreateInviteResult`].
///
/// Wire layout:
/// ```text
/// [0] status u8 (pair_source_status::*)
/// [1..3] uri_len u16 BE (0 on non-OK)
/// [3..3+uri_len] uri UTF-8 bytes
/// [..] detail_len u16 BE
/// [..] detail UTF-8 bytes
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairSourceCreateInviteResultPayload {
    pub status: u8,
    pub uri: String,
    pub detail: Vec<u8>,
}

impl PairSourceCreateInviteResultPayload {
    const FIXED: usize = 1 + 2;
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::FIXED + self.uri.len() + 2 + self.detail.len());
        buf.push(self.status);
        buf.extend_from_slice(&(self.uri.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.uri.as_bytes());
        buf.extend_from_slice(&(self.detail.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.detail);
        buf
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED,
                got: buf.len(),
            });
        }
        let status = buf[0];
        let uri_len = super::read_u16_be(buf, 1)? as usize;
        if uri_len > MAX_PAIR_URI_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "pair_source_create_result.uri_len",
                value: uri_len as u64,
                max: MAX_PAIR_URI_LEN as u64,
            });
        }
        let uri_end = Self::FIXED + uri_len;
        if buf.len() < uri_end + 2 {
            return Err(ProtoError::BufferTooShort {
                need: uri_end + 2,
                got: buf.len(),
            });
        }
        let uri = std::str::from_utf8(&buf[Self::FIXED..uri_end])
            .map_err(|_| ProtoError::InvalidUtf8)?
            .to_string();
        let detail_len = super::read_u16_be(buf, uri_end)? as usize;
        if detail_len > MAX_PAIR_DETAIL_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "pair_source_create_result.detail_len",
                value: detail_len as u64,
                max: MAX_PAIR_DETAIL_LEN as u64,
            });
        }
        let total = uri_end + 2 + detail_len;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            status,
            uri,
            detail: buf[uri_end + 2..total].to_vec(),
        })
    }
}

/// Generic length-prefixed-bytes payload for opaque pairing-frame
/// transport across IPC.  Used by 4 messages (Hello / Cert / Confirm
/// requests from one side to the other).  Single struct so encode/decode
/// stays one place.
///
/// Wire: `[0..4] bytes_len u32 BE`, `[4..] bytes`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairCeremonyFramePayload {
    pub bytes: Vec<u8>,
}

impl PairCeremonyFramePayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.bytes.len());
        buf.extend_from_slice(&(self.bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.bytes);
        buf
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 4 {
            return Err(ProtoError::BufferTooShort {
                need: 4,
                got: buf.len(),
            });
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len > MAX_PAIR_CEREMONY_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "pair_ceremony_frame.len",
                value: len as u64,
                max: MAX_PAIR_CEREMONY_BYTES as u64,
            });
        }
        if buf.len() < 4 + len {
            return Err(ProtoError::BufferTooShort {
                need: 4 + len,
                got: buf.len(),
            });
        }
        Ok(Self {
            bytes: buf[4..4 + len].to_vec(),
        })
    }
}

/// Payload [`crate::family::LocalAppMsg::PairSourceHandleHelloResult`]
/// and [`crate::family::LocalAppMsg::PairTargetHandleCertResult`].  Both
/// reply with (status, cert-or-empty bytes, 6-digit OOB code or empty,
/// detail).  Sharing one type keeps wire surface area small.
///
/// Wire layout:
/// ```text
/// [0] status u8
/// [1..7] oob_code 6 ASCII digits (zero-filled on non-OK)
/// [7..11] response_bytes_len u32 BE
/// [11..11+resp_len] response_bytes
/// [..] detail_len u16 BE
/// [..] detail bytes
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairCeremonyOobResultPayload {
    pub status: u8,
    /// 6-digit OOB code as ASCII bytes (e.g. b"012345"); all-zero on non-OK.
    pub oob_code: [u8; PAIR_OOB_CODE_LEN],
    /// On Source.handle_hello: Cert bytes for transport to Target.
    /// On Target.handle_cert: empty (Target keeps state internally).
    pub response_bytes: Vec<u8>,
    pub detail: Vec<u8>,
}

impl PairCeremonyOobResultPayload {
    const FIXED: usize = 1 + PAIR_OOB_CODE_LEN + 4;
    pub fn encode(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(Self::FIXED + self.response_bytes.len() + 2 + self.detail.len());
        buf.push(self.status);
        buf.extend_from_slice(&self.oob_code);
        buf.extend_from_slice(&(self.response_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.response_bytes);
        buf.extend_from_slice(&(self.detail.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.detail);
        buf
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED,
                got: buf.len(),
            });
        }
        let status = buf[0];
        let mut oob_code = [0u8; PAIR_OOB_CODE_LEN];
        oob_code.copy_from_slice(&buf[1..1 + PAIR_OOB_CODE_LEN]);
        let resp_len = u32::from_be_bytes([
            buf[1 + PAIR_OOB_CODE_LEN],
            buf[2 + PAIR_OOB_CODE_LEN],
            buf[3 + PAIR_OOB_CODE_LEN],
            buf[4 + PAIR_OOB_CODE_LEN],
        ]) as usize;
        if resp_len > MAX_PAIR_CEREMONY_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "pair_oob_result.resp_len",
                value: resp_len as u64,
                max: MAX_PAIR_CEREMONY_BYTES as u64,
            });
        }
        let resp_end = Self::FIXED + resp_len;
        if buf.len() < resp_end + 2 {
            return Err(ProtoError::BufferTooShort {
                need: resp_end + 2,
                got: buf.len(),
            });
        }
        let detail_len = super::read_u16_be(buf, resp_end)? as usize;
        if detail_len > MAX_PAIR_DETAIL_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "pair_oob_result.detail_len",
                value: detail_len as u64,
                max: MAX_PAIR_DETAIL_LEN as u64,
            });
        }
        let total = resp_end + 2 + detail_len;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            status,
            oob_code,
            response_bytes: buf[Self::FIXED..resp_end].to_vec(),
            detail: buf[resp_end + 2..total].to_vec(),
        })
    }
}

/// Simple status-only reply payload for ops that just acknowledge.
/// Used by `PairSourceHandleConfirmResult`, `PairTargetBuildConfirmResult`,
/// `PairTargetConsumeUriResult` (latter also carries Hello bytes — but
/// uses [`PairCeremonyFrameResultPayload`] instead).
///
/// Wire: `[0] status u8`, `[1..3] detail_len u16 BE`, `[3..] detail`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairStatusResultPayload {
    pub status: u8,
    pub detail: Vec<u8>,
}

impl PairStatusResultPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(3 + self.detail.len());
        buf.push(self.status);
        buf.extend_from_slice(&(self.detail.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.detail);
        buf
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 3 {
            return Err(ProtoError::BufferTooShort {
                need: 3,
                got: buf.len(),
            });
        }
        let status = buf[0];
        let detail_len = super::read_u16_be(buf, 1)? as usize;
        if detail_len > MAX_PAIR_DETAIL_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "pair_status_result.detail_len",
                value: detail_len as u64,
                max: MAX_PAIR_DETAIL_LEN as u64,
            });
        }
        if buf.len() < 3 + detail_len {
            return Err(ProtoError::BufferTooShort {
                need: 3 + detail_len,
                got: buf.len(),
            });
        }
        Ok(Self {
            status,
            detail: buf[3..3 + detail_len].to_vec(),
        })
    }
}

/// Reply payload carrying status + opaque bytes + detail.  Used by
/// `PairTargetConsumeUriResult` (carries Hello bytes to transport to Source).
///
/// Wire: `[0] status u8`, `[1..5] bytes_len u32 BE`, `[5..] bytes`,
///       `[..] detail_len u16 BE`, `[..] detail`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairCeremonyFrameResultPayload {
    pub status: u8,
    pub bytes: Vec<u8>,
    pub detail: Vec<u8>,
}

impl PairCeremonyFrameResultPayload {
    const FIXED: usize = 1 + 4;
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::FIXED + self.bytes.len() + 2 + self.detail.len());
        buf.push(self.status);
        buf.extend_from_slice(&(self.bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.bytes);
        buf.extend_from_slice(&(self.detail.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.detail);
        buf
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED,
                got: buf.len(),
            });
        }
        let status = buf[0];
        let bytes_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if bytes_len > MAX_PAIR_CEREMONY_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "pair_frame_result.bytes_len",
                value: bytes_len as u64,
                max: MAX_PAIR_CEREMONY_BYTES as u64,
            });
        }
        let bytes_end = Self::FIXED + bytes_len;
        if buf.len() < bytes_end + 2 {
            return Err(ProtoError::BufferTooShort {
                need: bytes_end + 2,
                got: buf.len(),
            });
        }
        let detail_len = super::read_u16_be(buf, bytes_end)? as usize;
        if detail_len > MAX_PAIR_DETAIL_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "pair_frame_result.detail_len",
                value: detail_len as u64,
                max: MAX_PAIR_DETAIL_LEN as u64,
            });
        }
        let total = bytes_end + 2 + detail_len;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            status,
            bytes: buf[Self::FIXED..bytes_end].to_vec(),
            detail: buf[bytes_end + 2..total].to_vec(),
        })
    }
}

/// Payload [`crate::family::LocalAppMsg::PairTargetConsumeUri`].
/// Wire: `[0..2] uri_len u16 BE`, `[2..2+uri] uri UTF-8`, then an OPTIONAL
/// trailing label block `[label_len u16 BE][label UTF-8]` (Phase 4). Legacy
/// uri-only buffers (no trailing bytes) decode to `instance_label = None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairTargetConsumeUriPayload {
    pub uri: String,
    /// Optional human display label for the newly-paired device (Phase 4).
    /// Wire-appended after the uri block; legacy uri-only payloads decode to
    /// `None`. Capped at [`crate::instance_registry::MAX_LABEL_BYTES`].
    pub instance_label: Option<String>,
}

impl PairTargetConsumeUriPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.uri.len());
        buf.extend_from_slice(&(self.uri.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.uri.as_bytes());
        // Append the label block ONLY when present, so a `None` payload is
        // byte-identical to the legacy uri-only encoding (backward-compat).
        if let Some(label) = self.instance_label.as_deref() {
            buf.extend_from_slice(&(label.len() as u16).to_be_bytes());
            buf.extend_from_slice(label.as_bytes());
        }
        buf
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 2 {
            return Err(ProtoError::BufferTooShort {
                need: 2,
                got: buf.len(),
            });
        }
        let uri_len = super::read_u16_be(buf, 0)? as usize;
        if uri_len > MAX_PAIR_URI_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "pair_consume_uri.uri_len",
                value: uri_len as u64,
                max: MAX_PAIR_URI_LEN as u64,
            });
        }
        if buf.len() < 2 + uri_len {
            return Err(ProtoError::BufferTooShort {
                need: 2 + uri_len,
                got: buf.len(),
            });
        }
        let uri = std::str::from_utf8(&buf[2..2 + uri_len])
            .map_err(|_| ProtoError::InvalidUtf8)?
            .to_string();
        // Optional trailing instance_label (Phase 4). Absent on legacy payloads.
        let rest = &buf[2 + uri_len..];
        let instance_label = if rest.is_empty() {
            None
        } else {
            if rest.len() < 2 {
                return Err(ProtoError::BufferTooShort {
                    need: 2,
                    got: rest.len(),
                });
            }
            let label_len = super::read_u16_be(rest, 0)? as usize;
            if label_len > crate::instance_registry::MAX_LABEL_BYTES {
                return Err(ProtoError::ValueTooLarge {
                    field: "pair_consume_uri.label_len",
                    value: label_len as u64,
                    max: crate::instance_registry::MAX_LABEL_BYTES as u64,
                });
            }
            if rest.len() < 2 + label_len {
                return Err(ProtoError::BufferTooShort {
                    need: 2 + label_len,
                    got: rest.len(),
                });
            }
            Some(
                std::str::from_utf8(&rest[2..2 + label_len])
                    .map_err(|_| ProtoError::InvalidUtf8)?
                    .to_string(),
            )
        };
        Ok(Self {
            uri,
            instance_label,
        })
    }
}

/// Payload [`crate::family::LocalAppMsg::PairTargetBuildConfirm`].
/// Wire: `[0] confirmed u8` (0 = user aborted, 1 = codes match).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairTargetBuildConfirmPayload {
    pub confirmed: bool,
}

impl PairTargetBuildConfirmPayload {
    pub fn encode(&self) -> Vec<u8> {
        vec![if self.confirmed { 1 } else { 0 }]
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.is_empty() {
            return Err(ProtoError::BufferTooShort { need: 1, got: 0 });
        }
        Ok(Self {
            confirmed: buf[0] != 0,
        })
    }
}

// ── Mobile-status query ────────────────────────────────────────

/// Sentinel for `low_battery_threshold_pct` when battery-aware
/// route-probe throttling is disabled (matches the `Option::None` case
/// at the runtime level — apps display this as "feature off").
pub const MOBILE_LOW_BATTERY_THRESHOLD_DISABLED: u8 = 255;

/// Sentinel for `battery_level_pct` when running on AC / unknown
/// hardware / non-Linux platform — never throttled on this signal by
/// design. Apps display this as "AC / unknown" rather than "100%".
pub const MOBILE_BATTERY_AC_OR_UNKNOWN: u8 = 100;

/// Payload [`crate::family::LocalAppMsg::MobileStatus`].
///
/// Mirrors `veilcore::node::admin::AdminMobileStatus` field-for-field
/// so the IPC handler can build the wire payload directly from the
/// existing runtime helper. All fields stay typed wire bytes (no
/// JSON), keeping the payload compact (≤ 16 bytes typical) and the
/// decoder allocation-free.
///
/// Wire layout:
/// ```text
/// [0] background_tier u8 (0=Foreground, 1=Active, 2=LowPower)
/// [1..5] background_keepalive_mult u32 BE (configured cap, e.g. 60)
/// [5..9] background_keepalive_factor u32 BE (effective factor RIGHT NOW)
/// [9] battery_level_pct u8 (0-100; 100 = AC / unknown)
/// [10] low_battery_threshold_pct u8 (0-100; 255 = disabled)
/// [11..15] low_battery_multiplier u32 BE (configured cap, e.g. 4)
/// [15..19] battery_route_probe_factor u32 BE (effective factor RIGHT NOW)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MobileStatusPayload {
    /// Current background tier: 0=Foreground / 1=Active / 2=LowPower.
    pub background_tier: u8,
    /// Configured `mobile.background_keepalive_multiplier`.
    pub background_keepalive_multiplier: u32,
    /// Effective background-keepalive factor RIGHT NOW.
    pub background_keepalive_factor: u32,
    /// Current battery reading (0-100). `100` = AC / unknown.
    pub battery_level_pct: u8,
    /// Configured `mobile.low_battery_threshold_pct`.
    /// `255` = disabled (feature off).
    pub low_battery_threshold_pct: u8,
    /// Configured `mobile.low_battery_multiplier`.
    pub low_battery_multiplier: u32,
    /// Effective route-probe battery throttle factor RIGHT NOW.
    pub battery_route_probe_factor: u32,
}

impl MobileStatusPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 1 + 4 + 4 + 1 + 1 + 4 + 4;

    /// Encode to the fixed 19-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0] = self.background_tier;
        buf[1..5].copy_from_slice(&self.background_keepalive_multiplier.to_be_bytes());
        buf[5..9].copy_from_slice(&self.background_keepalive_factor.to_be_bytes());
        buf[9] = self.battery_level_pct;
        buf[10] = self.low_battery_threshold_pct;
        buf[11..15].copy_from_slice(&self.low_battery_multiplier.to_be_bytes());
        buf[15..19].copy_from_slice(&self.battery_route_probe_factor.to_be_bytes());
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let background_tier = buf[0];
        let background_keepalive_multiplier = super::read_u32_be(buf, 1)?;
        let background_keepalive_factor = super::read_u32_be(buf, 5)?;
        let battery_level_pct = buf[9];
        let low_battery_threshold_pct = buf[10];
        let low_battery_multiplier = super::read_u32_be(buf, 11)?;
        let battery_route_probe_factor = super::read_u32_be(buf, 15)?;
        Ok(Self {
            background_tier,
            background_keepalive_multiplier,
            background_keepalive_factor,
            battery_level_pct,
            low_battery_threshold_pct,
            low_battery_multiplier,
            battery_route_probe_factor,
        })
    }
}

// ── Push event stream ──────────────

/// Hard cap on `EventPayload.payload` byte length. Per-event payloads are
/// tiny by design (status snapshots are 8-32 B; even a peer-list-changed
/// snapshot fits in low KiB). 4 KiB ceiling defends against pathological
/// publisher mistakes that would blow the IPC frame budget.
pub const MAX_EVENT_PAYLOAD_LEN: usize = 4096;

/// Event-kind wire byte [`EventPayload::kind`]. Kinds are kept stable —
/// adding new kinds is forward-compatible (older clients ignore unknown
/// kinds; newer clients dispatch on the known set).
pub mod event_kind {
    /// Active session count changed.
    /// Payload: `[u16 BE active_session_count]` (2 bytes).
    pub const SESSIONS_CHANGED: u8 = 0;
    /// Mobile background tier transitioned (Foreground/Active/LowPower).
    /// Payload: `[u8 tier]` (1 byte; matches `MobileBackgroundMode`).
    pub const MOBILE_TIER_CHANGED: u8 = 1;
    /// Local node identity rotated (rare event — operator triggered or
    /// recovery from compromise). Payload: `[u8; 32] new_node_id`.
    pub const IDENTITY_ROTATED: u8 = 2;
    /// Mailbox drain (fetch) completed. Published after every authorised
    /// fetch returns, including the empty-result path. Allows a consumer
    /// background-handler (iOS BGProcessingTask, Android JobScheduler)
    /// to `setTaskCompleted` precisely when the daemon has finished
    /// draining pending wake-triggered work — rather than padding to a
    /// hardcoded ceiling.  Payload: `[u32 BE drained_count]` (4 bytes;
    /// number of blobs returned in this fetch).
    pub const MAILBOX_DRAINED: u8 = 3;
    /// An authenticated/anonymous send the daemon accepted for transmission
    /// later failed asynchronously (diff-audit L7). The send API is
    /// fire-and-forget — it returns success once the cell is handed to the first
    /// hop — so a failure detected afterwards (no route, terminal NACK) surfaces
    /// here rather than as a return value. Best-effort / informational: there is
    /// no end-to-end ACK, so absence of this event is NOT proof of delivery.
    /// Payload: `[u8; 32] content_id` of the failed message.
    pub const ANON_SEND_FAILED: u8 = 4;
}

/// Payload [`crate::family::LocalAppMsg::Event`].
///
/// Tagged-union wire format: a 1-byte `kind` selects the meaning of the
/// `payload` bytes, which the receiving SDK dispatches to a per-kind
/// decoder. Forward-compat: SDKs that don't recognise a `kind` byte
/// pass the raw event to a fallback handler so they don't crash on
/// future event types.
///
/// Wire layout:
/// ```text
/// [0] kind u8 (event_kind::*)
/// [1..3] payload_len u16 BE (≤ MAX_EVENT_PAYLOAD_LEN)
/// [3..3+payload_len] payload bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPayload {
    /// Event kind (see [`event_kind`]).
    pub kind: u8,
    /// Per-kind opaque payload. Length-prefixed and length-bounded.
    pub payload: Vec<u8>,
}

impl EventPayload {
    /// Fixed wire-prefix size before the variable payload.
    pub const FIXED_SIZE: usize = 1 + 2;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.payload.len() <= MAX_EVENT_PAYLOAD_LEN,
            "payload exceeds MAX_EVENT_PAYLOAD_LEN"
        );
        debug_assert!(
            self.payload.len() <= u16::MAX as usize,
            "payload length must fit in u16"
        );
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + self.payload.len());
        buf.push(self.kind);
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let kind = buf[0];
        let payload_len = super::read_u16_be(buf, 1)? as usize;
        if payload_len > MAX_EVENT_PAYLOAD_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "event.payload_len",
                value: payload_len as u64,
                max: MAX_EVENT_PAYLOAD_LEN as u64,
            });
        }
        // checked_add — 32-bit overflow defence.
        let total =
            Self::FIXED_SIZE
                .checked_add(payload_len)
                .ok_or(ProtoError::BufferTooShort {
                    need: usize::MAX,
                    got: buf.len(),
                })?;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok(Self {
            kind,
            payload: buf[Self::FIXED_SIZE..total].to_vec(),
        })
    }
}

// ── PnetStatusQuery / PnetStatusResult ─────────────────────────────────────

/// Reply to [`crate::family::LocalAppMsg::PnetStatusQuery`].  The daemon
/// looks up its `NetworkAccessGate` cache for the queried peer and
/// reports whether the OVL1 session was admitted under a valid
/// `MembershipCert`.
///
/// Wire layout (fixed 74 bytes):
/// ```text
/// [0]        admitted        u8 (0 = no, 1 = yes)
/// [1]        has_cert        u8 (0 = no, 1 = yes — daemon cached a cert)
/// [2]        admin           u8 (0/1; meaningful only when has_cert=1)
/// [3..11]    valid_until_unix u64 BE (0 = never expires; meaningful only when has_cert=1)
/// [11..43]   network_id      [u8; 32] (zeros when has_cert=0)
/// [43..75]   peer_node_id    [u8; 32] (echoes the query for correlation)
/// ```
///
/// Semantics:
/// * `admitted=1` AND `has_cert=1` ⇒ peer presented a valid cert; the
///   `network_id` / `admin` / `valid_until_unix` fields are from that
///   cert. Use case: ogate/oproxy admission in "p_net" mode.
/// * `admitted=1` AND `has_cert=0` ⇒ daemon admits because P-Net is not
///   enabled OR the session predates cert verification. Apps in strict
///   p_net mode SHOULD reject this case (treat as "no cert presented").
/// * `admitted=0` ⇒ no active session to the queried peer, or the session
///   was rejected during handshake. Apps reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PnetStatusResultPayload {
    /// Whether there's an active veil session to `peer_node_id`.
    pub admitted: bool,
    /// Whether the daemon has a verified `MembershipCert` for this peer
    /// (always false unless P-Net is configured in the daemon).
    pub has_cert: bool,
    /// Cert admin flag (only meaningful when `has_cert == true`).
    pub admin: bool,
    /// Cert expiry. `0` ⇒ sentinel "no expiry"; otherwise unix seconds.
    pub valid_until_unix: u64,
    /// Cert's network_id (zeros when `has_cert == false`).
    pub network_id: [u8; 32],
    /// Echoed peer_node_id from the query (correlation in pipelined IPC).
    pub peer_node_id: [u8; 32],
}

impl PnetStatusResultPayload {
    pub const WIRE_SIZE: usize = 1 + 1 + 1 + 8 + 32 + 32;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0] = u8::from(self.admitted);
        buf[1] = u8::from(self.has_cert);
        buf[2] = u8::from(self.admin);
        buf[3..11].copy_from_slice(&self.valid_until_unix.to_be_bytes());
        buf[11..43].copy_from_slice(&self.network_id);
        buf[43..75].copy_from_slice(&self.peer_node_id);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() != Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let mut valid_until_bytes = [0u8; 8];
        valid_until_bytes.copy_from_slice(&buf[3..11]);
        let mut network_id = [0u8; 32];
        network_id.copy_from_slice(&buf[11..43]);
        let mut peer_node_id = [0u8; 32];
        peer_node_id.copy_from_slice(&buf[43..75]);
        Ok(Self {
            admitted: buf[0] != 0,
            has_cert: buf[1] != 0,
            admin: buf[2] != 0,
            valid_until_unix: u64::from_be_bytes(valid_until_bytes),
            network_id,
            peer_node_id,
        })
    }
}

// ── Offline-mailbox seal/open (node-side E2E crypto, distinct from the
//    MailboxPut/Fetch/Ack relay transport) ─────────────────────────────────────

/// Result status shared by [`MailboxSealResultPayload`] and
/// [`MailboxOpenResultPayload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MailboxCryptoStatus {
    /// Success — the sealed blob (seal) / verified message (open) follows.
    Ok = 0,
    /// No sovereign identity is loaded on the node.
    NoIdentity = 1,
    /// The peer's ML-KEM cert (seal) or identity document (open) could not be
    /// resolved + verified from the DHT.
    PeerUnresolved = 2,
    /// The seal/open operation itself failed (encrypt, decode, AEAD, size, or
    /// signature verification).
    Failed = 3,
}

impl MailboxCryptoStatus {
    /// Status byte.
    pub fn to_wire(self) -> u8 {
        self as u8
    }
    /// Parse from the status byte.
    pub fn from_wire(b: u8) -> Result<Self, ProtoError> {
        match b {
            0 => Ok(Self::Ok),
            1 => Ok(Self::NoIdentity),
            2 => Ok(Self::PeerUnresolved),
            3 => Ok(Self::Failed),
            other => Err(ProtoError::Malformed(format!(
                "MailboxCryptoStatus: unknown status byte {other}"
            ))),
        }
    }
}

/// Payload [`crate::family::LocalAppMsg::MailboxSeal`] (app → node).
///
/// Wire layout: `[recipient_node_id(32) | app_id(32) | endpoint_id_u32_be(4) | data(rest)]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxSealPayload {
    /// Recipient the message is sealed for.
    pub recipient_node_id: [u8; 32],
    /// Destination app id at the recipient.
    pub app_id: [u8; 32],
    /// Destination endpoint id at the recipient.
    pub endpoint_id: u32,
    /// Plaintext to seal.
    pub data: Vec<u8>,
}

impl MailboxSealPayload {
    /// Fixed-prefix size before the variable `data`.
    pub const HEADER_SIZE: usize = 32 + 32 + 4;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.data.len());
        buf.extend_from_slice(&self.recipient_node_id);
        buf.extend_from_slice(&self.app_id);
        buf.extend_from_slice(&self.endpoint_id.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let recipient_node_id = super::read_array::<32>(buf, 0)?;
        let app_id = super::read_array::<32>(buf, 32)?;
        let endpoint_id = super::read_u32_be(buf, 64)?;
        let data = buf[Self::HEADER_SIZE..].to_vec();
        Ok(Self {
            recipient_node_id,
            app_id,
            endpoint_id,
            data,
        })
    }
}

/// Payload [`crate::family::LocalAppMsg::MailboxSealOk`] (node → app).
///
/// Wire layout: `[status(1) | blob(rest)]`. `blob` is the sealed mailbox blob,
/// present only when `status == Ok`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxSealResultPayload {
    /// Outcome of the seal.
    pub status: MailboxCryptoStatus,
    /// The sealed blob (empty unless `status == Ok`).
    pub blob: Vec<u8>,
}

impl MailboxSealResultPayload {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.blob.len());
        buf.push(self.status.to_wire());
        buf.extend_from_slice(&self.blob);
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let status = MailboxCryptoStatus::from_wire(
            *buf.first()
                .ok_or(ProtoError::BufferTooShort { need: 1, got: 0 })?,
        )?;
        Ok(Self {
            status,
            blob: buf[1..].to_vec(),
        })
    }
}

/// Payload [`crate::family::LocalAppMsg::MailboxOpen`] (app → node).
///
/// Wire layout: `[sender_node_id(32) | our_cert_version_u64_be(8) | blob(rest)]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxOpenPayload {
    /// Claimed sender (whose document the node resolves to verify the blob).
    pub sender_node_id: [u8; 32],
    /// Version of OUR currently-published ML-KEM cert (matches our `dk_seed`).
    pub our_cert_version: u64,
    /// The fetched mailbox blob to open + verify.
    pub blob: Vec<u8>,
}

impl MailboxOpenPayload {
    /// Fixed-prefix size before the variable `blob`.
    pub const HEADER_SIZE: usize = 32 + 8;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.blob.len());
        buf.extend_from_slice(&self.sender_node_id);
        buf.extend_from_slice(&self.our_cert_version.to_be_bytes());
        buf.extend_from_slice(&self.blob);
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let sender_node_id = super::read_array::<32>(buf, 0)?;
        let our_cert_version = super::read_u64_be(buf, 32)?;
        let blob = buf[Self::HEADER_SIZE..].to_vec();
        Ok(Self {
            sender_node_id,
            our_cert_version,
            blob,
        })
    }
}

/// Payload [`crate::family::LocalAppMsg::MailboxOpenOk`] (node → app).
///
/// Wire layout: `[status(1) | app_id(32) | endpoint_id_u32_be(4) | data(rest)]`.
/// `app_id` / `endpoint_id` / `data` carry the verified [`AuthAppDeliver`]'s
/// routing target + payload, present only when `status == Ok`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxOpenResultPayload {
    /// Outcome of the open + verify.
    pub status: MailboxCryptoStatus,
    /// Verified destination app id.
    pub app_id: [u8; 32],
    /// Verified destination endpoint id.
    pub endpoint_id: u32,
    /// Verified plaintext.
    pub data: Vec<u8>,
}

impl MailboxOpenResultPayload {
    /// Fixed-prefix size before the variable `data`.
    pub const HEADER_SIZE: usize = 1 + 32 + 4;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.data.len());
        buf.push(self.status.to_wire());
        buf.extend_from_slice(&self.app_id);
        buf.extend_from_slice(&self.endpoint_id.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let status = MailboxCryptoStatus::from_wire(buf[0])?;
        let app_id = super::read_array::<32>(buf, 1)?;
        let endpoint_id = super::read_u32_be(buf, 33)?;
        let data = buf[Self::HEADER_SIZE..].to_vec();
        Ok(Self {
            status,
            app_id,
            endpoint_id,
            data,
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_seal_payloads_round_trip() {
        let req = MailboxSealPayload {
            recipient_node_id: [0xA1; 32],
            app_id: [0xB2; 32],
            endpoint_id: 0x0102_0304,
            data: b"seal me".to_vec(),
        };
        assert_eq!(MailboxSealPayload::decode(&req.encode()).unwrap(), req);

        let ok = MailboxSealResultPayload {
            status: MailboxCryptoStatus::Ok,
            blob: vec![1, 2, 3, 4, 5],
        };
        assert_eq!(MailboxSealResultPayload::decode(&ok.encode()).unwrap(), ok);
        // Error result carries an empty blob.
        let err = MailboxSealResultPayload {
            status: MailboxCryptoStatus::PeerUnresolved,
            blob: Vec::new(),
        };
        assert_eq!(MailboxSealResultPayload::decode(&err.encode()).unwrap(), err);
    }

    #[test]
    fn mailbox_open_payloads_round_trip() {
        let req = MailboxOpenPayload {
            sender_node_id: [0xC3; 32],
            our_cert_version: 0xDEAD_BEEF_0000_0007,
            blob: b"an opaque sealed blob".to_vec(),
        };
        assert_eq!(MailboxOpenPayload::decode(&req.encode()).unwrap(), req);

        let ok = MailboxOpenResultPayload {
            status: MailboxCryptoStatus::Ok,
            app_id: [0x44; 32],
            endpoint_id: 9,
            data: b"recovered plaintext".to_vec(),
        };
        assert_eq!(MailboxOpenResultPayload::decode(&ok.encode()).unwrap(), ok);
    }

    #[test]
    fn mailbox_crypto_status_round_trips_and_rejects_unknown() {
        for s in [
            MailboxCryptoStatus::Ok,
            MailboxCryptoStatus::NoIdentity,
            MailboxCryptoStatus::PeerUnresolved,
            MailboxCryptoStatus::Failed,
        ] {
            assert_eq!(MailboxCryptoStatus::from_wire(s.to_wire()).unwrap(), s);
        }
        assert!(MailboxCryptoStatus::from_wire(99).is_err());
    }

    #[test]
    fn mailbox_seal_open_reject_truncated_headers() {
        assert!(MailboxSealPayload::decode(&[0u8; 67]).is_err()); // < 68
        assert!(MailboxOpenPayload::decode(&[0u8; 39]).is_err()); // < 40
        assert!(MailboxOpenResultPayload::decode(&[0u8; 36]).is_err()); // < 37
        assert!(MailboxSealResultPayload::decode(&[]).is_err()); // empty
    }

    #[test]
    fn send_to_onion_service_payload_roundtrip() {
        // Authenticated mode (anonymous = false; src_app_id preserved on wire).
        let p = SendToOnionServicePayload {
            service_identity_vk: [0x1A; 32],
            target_app_id: [0x2B; 32],
            target_endpoint_id: 0xDEAD_BEEF,
            hop_count: 3,
            anonymous: false,
            src_app_id: [0x3C; 32],
            data: b"hello onion service".to_vec(),
        };
        let bytes = p.encode();
        assert_eq!(
            bytes.len(),
            SendToOnionServicePayload::FIXED_SIZE + p.data.len()
        );
        assert_eq!(SendToOnionServicePayload::decode(&bytes).unwrap(), p);
    }

    #[test]
    fn send_to_onion_service_payload_anonymous_flag_roundtrip() {
        let p = SendToOnionServicePayload {
            service_identity_vk: [0x44; 32],
            target_app_id: [0x55; 32],
            target_endpoint_id: 7,
            hop_count: 2,
            anonymous: true,
            src_app_id: [0x66; 32],
            data: Vec::new(),
        };
        let bytes = p.encode();
        assert_eq!(bytes.len(), SendToOnionServicePayload::FIXED_SIZE);
        let decoded = SendToOnionServicePayload::decode(&bytes).unwrap();
        assert!(decoded.anonymous);
        assert_eq!(decoded, p);
    }

    #[test]
    fn send_to_onion_service_payload_short_buf_errs() {
        assert!(SendToOnionServicePayload::decode(&[0u8; 104]).is_err());
    }

    #[test]
    fn send_anonymous_direct_payload_roundtrip() {
        let p = SendAnonymousDirectPayload {
            target_node_id: [0x11; 32],
            target_x25519_pk: [0x22; 32],
            target_app_id: [0x33; 32],
            src_app_id: [0x44; 32],
            target_endpoint_id: 0xCAFE,
            hop_count: 3,
            data: b"direct anon".to_vec(),
        };
        let bytes = p.encode();
        assert_eq!(
            bytes.len(),
            SendAnonymousDirectPayload::FIXED_SIZE + p.data.len()
        );
        assert_eq!(SendAnonymousDirectPayload::decode(&bytes).unwrap(), p);
    }

    #[test]
    fn send_anonymous_direct_payload_short_buf_errs() {
        assert!(SendAnonymousDirectPayload::decode(&[0u8; 135]).is_err());
    }

    fn sample_auth_deliver() -> AuthAppDeliver {
        AuthAppDeliver {
            version: AuthAppDeliver::VERSION,
            sender_node_id: [0xAA; 32],
            sig_key_idx: 3,
            timestamp: 1_700_000_123,
            nonce: 0x0123_4567_89AB_CDEF,
            dst_node_id: [0xBB; 32],
            app_id: [0xCC; 32],
            endpoint_id: 42,
            data: b"hi bob, it's authentically alice".to_vec(),
            reply_block: None,
            signature: vec![0x5A; 64], // Ed25519-sized
        }
    }

    #[test]
    fn auth_app_deliver_roundtrip() {
        let p = sample_auth_deliver();
        let decoded = AuthAppDeliver::decode(&p.encode()).expect("decode");
        // `dst_node_id` is signed but NOT on the wire — decode zeroes it, the
        // verifier reconstructs it as its own node_id. Every other field round
        // trips.
        assert_eq!(decoded.dst_node_id, [0u8; 32]);
        let mut expected = p.clone();
        expected.dst_node_id = [0u8; 32];
        assert_eq!(decoded, expected);
    }

    #[test]
    fn auth_app_deliver_dst_bound_in_signature_not_on_wire() {
        let p = sample_auth_deliver();
        // The 32-byte dst run does NOT appear on the wire.
        assert!(
            !p.encode().windows(32).any(|w| w == p.dst_node_id),
            "dst_node_id must not be transmitted",
        );
        // But two different dsts produce different signing bytes (binding).
        assert_ne!(
            p.signing_bytes_with_dst(&[0x01; 32]),
            p.signing_bytes_with_dst(&[0x02; 32]),
        );
        // And the sender-side `signing_bytes` binds `self.dst_node_id`.
        assert_eq!(p.signing_bytes(), p.signing_bytes_with_dst(&p.dst_node_id));
    }

    #[test]
    fn auth_app_deliver_signing_bytes_exclude_signature_and_bind_fields() {
        let p = sample_auth_deliver();
        let sb = p.signing_bytes();
        // Domain-prefixed, and the signature is NOT part of the signed bytes.
        assert!(sb.starts_with(AUTH_APP_DELIVER_DOMAIN));
        let mut windows = sb.windows(p.signature.len());
        // a 64-byte run of 0x5A (the signature) must not appear in signing_bytes.
        assert!(
            !windows.any(|w| w == p.signature.as_slice()),
            "signature bytes must not be covered by signing_bytes",
        );
        // Changing any bound field changes signing_bytes (sample: dst_node_id).
        let mut q = p.clone();
        q.dst_node_id = [0x00; 32];
        assert_ne!(q.signing_bytes(), sb);
        // Changing ONLY the signature does NOT change signing_bytes.
        let mut r = p.clone();
        r.signature = vec![0x11; 64];
        assert_eq!(r.signing_bytes(), sb);
    }

    #[test]
    fn auth_app_deliver_rejects_bad_version_and_oversize_sig() {
        let mut bytes = sample_auth_deliver().encode();
        bytes[0] = 2; // unsupported version
        assert!(matches!(
            AuthAppDeliver::decode(&bytes),
            Err(ProtoError::Malformed(_))
        ));

        // Oversize signature length field → rejected by the cap.
        let mut p = sample_auth_deliver();
        p.signature = vec![0u8; AuthAppDeliver::MAX_SIG_LEN + 1];
        assert!(matches!(
            AuthAppDeliver::decode(&p.encode()),
            Err(ProtoError::Malformed(_))
        ));
    }

    fn sample_reply_block() -> ReplyBlock {
        ReplyBlock {
            rendezvous_node_id: [0x11; 32],
            auth_cookie: [0x22; 16],
            x25519_pk: [0x33; 32],
            reply_app_id: [0x44; 32],
            reply_endpoint_id: 99,
            receiver_node_id: [0x55; 32],
        }
    }

    #[test]
    fn reply_block_roundtrip() {
        let rb = sample_reply_block();
        assert_eq!(rb.encode().len(), ReplyBlock::WIRE_SIZE);
        assert_eq!(ReplyBlock::decode(&rb.encode()).unwrap(), rb);
        assert!(ReplyBlock::decode(&[0u8; ReplyBlock::WIRE_SIZE - 1]).is_err());
    }

    #[test]
    fn auth_app_deliver_with_reply_block_roundtrips() {
        let mut p = sample_auth_deliver();
        p.reply_block = Some(sample_reply_block());
        let decoded = AuthAppDeliver::decode(&p.encode()).expect("decode");
        // Only dst_node_id is dropped on the wire; the reply block survives.
        let mut expected = p.clone();
        expected.dst_node_id = [0u8; 32];
        assert_eq!(decoded, expected);
        assert_eq!(decoded.reply_block, Some(sample_reply_block()));
    }

    #[test]
    fn auth_app_deliver_signing_binds_reply_block() {
        let none = sample_auth_deliver(); // reply_block: None
        let mut some = none.clone();
        some.reply_block = Some(sample_reply_block());
        // Presence of a reply block changes the signed bytes.
        assert_ne!(none.signing_bytes(), some.signing_bytes());
        // Altering the block's contents changes the signed bytes (unforgeable).
        let mut other = some.clone();
        other.reply_block.as_mut().unwrap().auth_cookie = [0xFF; 16];
        assert_ne!(some.signing_bytes(), other.signing_bytes());
    }

    #[test]
    fn auth_deliver_fragment_roundtrip() {
        let f = AuthDeliverFragment {
            msg_id: [0x7A; 16],
            frag_count: 5,
            frag_idx: 2,
            chunk: b"a slice of the signed AuthAppDeliver".to_vec(),
        };
        let decoded = AuthDeliverFragment::decode(&f.encode()).expect("decode");
        assert_eq!(decoded, f);
    }

    #[test]
    fn auth_deliver_fragment_rejects_bad_indices_and_empty() {
        let base = AuthDeliverFragment {
            msg_id: [0; 16],
            frag_count: 3,
            frag_idx: 0,
            chunk: vec![1, 2, 3],
        };
        // frag_idx >= frag_count.
        let mut bad = base.clone();
        bad.frag_idx = 3;
        assert!(matches!(
            AuthDeliverFragment::decode(&bad.encode()),
            Err(ProtoError::Malformed(_))
        ));
        // frag_count = 0.
        let mut zero = base.clone();
        zero.frag_count = 0;
        zero.frag_idx = 0;
        assert!(matches!(
            AuthDeliverFragment::decode(&zero.encode()),
            Err(ProtoError::Malformed(_))
        ));
        // frag_count over cap.
        let mut over = base.clone();
        over.frag_count = MAX_AUTH_DELIVER_FRAGMENTS + 1;
        assert!(matches!(
            AuthDeliverFragment::decode(&over.encode()),
            Err(ProtoError::Malformed(_))
        ));
        // Header-only (no chunk) → too short.
        assert!(AuthDeliverFragment::decode(&[0u8; AuthDeliverFragment::HEADER_SIZE]).is_err());
    }

    #[test]
    fn auth_app_deliver_truncated_inputs_error_not_panic() {
        let full = sample_auth_deliver().encode();
        for cut in [0usize, 1, 33, 50, 121, full.len() - 1] {
            assert!(
                AuthAppDeliver::decode(&full[..cut]).is_err(),
                "truncation at {cut} must error, not panic",
            );
        }
    }

    #[test]
    fn pnet_status_result_roundtrip() {
        let payload = PnetStatusResultPayload {
            admitted: true,
            has_cert: true,
            admin: false,
            valid_until_unix: 1_900_000_000,
            network_id: [0x11; 32],
            peer_node_id: [0x22; 32],
        };
        let encoded = payload.encode();
        assert_eq!(encoded.len(), PnetStatusResultPayload::WIRE_SIZE);
        let decoded = PnetStatusResultPayload::decode(&encoded).expect("roundtrip");
        assert_eq!(decoded, payload);
    }
    #[test]
    fn pair_consume_uri_roundtrip_with_and_without_label() {
        // With a label.
        let p = PairTargetConsumeUriPayload {
            uri: "veil:pair?x".to_string(),
            instance_label: Some("Alice's phone".to_string()),
        };
        assert_eq!(
            PairTargetConsumeUriPayload::decode(&p.encode()).expect("roundtrip"),
            p
        );
        // Without a label.
        let p2 = PairTargetConsumeUriPayload {
            uri: "veil:pair?y".to_string(),
            instance_label: None,
        };
        let enc2 = p2.encode();
        assert_eq!(PairTargetConsumeUriPayload::decode(&enc2).expect("rt"), p2);
        // Backward-compat: a None payload is byte-identical to the legacy
        // uri-only encoding, and a legacy buffer decodes to instance_label=None.
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&(p2.uri.len() as u16).to_be_bytes());
        legacy.extend_from_slice(p2.uri.as_bytes());
        assert_eq!(enc2, legacy, "None must equal the legacy uri-only wire");
        assert_eq!(
            PairTargetConsumeUriPayload::decode(&legacy)
                .unwrap()
                .instance_label,
            None
        );
        // Oversized label is rejected.
        let mut bad = Vec::new();
        bad.extend_from_slice(&3u16.to_be_bytes());
        bad.extend_from_slice(b"uri");
        bad.extend_from_slice(
            &((crate::instance_registry::MAX_LABEL_BYTES + 1) as u16).to_be_bytes(),
        );
        bad.extend_from_slice(&[b'a'; crate::instance_registry::MAX_LABEL_BYTES + 1]);
        assert!(PairTargetConsumeUriPayload::decode(&bad).is_err());
    }

    #[test]
    fn pnet_status_result_no_cert() {
        // admitted but no cert — apps in strict p_net mode must reject.
        let payload = PnetStatusResultPayload {
            admitted: true,
            has_cert: false,
            admin: false,
            valid_until_unix: 0,
            network_id: [0; 32],
            peer_node_id: [0x33; 32],
        };
        let decoded = PnetStatusResultPayload::decode(&payload.encode()).unwrap();
        assert!(decoded.admitted);
        assert!(!decoded.has_cert);
    }

    #[test]
    fn pnet_status_result_unlimited_cert() {
        // valid_until_unix=0 sentinel meaning "no expiry" — wire round-trips
        // the sentinel verbatim. Apps render this as NEVER.
        let payload = PnetStatusResultPayload {
            admitted: true,
            has_cert: true,
            admin: true,
            valid_until_unix: 0,
            network_id: [0x44; 32],
            peer_node_id: [0x55; 32],
        };
        let decoded = PnetStatusResultPayload::decode(&payload.encode()).unwrap();
        assert_eq!(decoded.valid_until_unix, 0);
    }

    #[test]
    fn pnet_status_result_truncated_rejected() {
        let buf = [0u8; PnetStatusResultPayload::WIRE_SIZE - 1];
        let err = PnetStatusResultPayload::decode(&buf).expect_err("truncated");
        matches!(err, ProtoError::BufferTooShort { .. });
    }

    #[test]
    fn hello_roundtrip() {
        let p = AppIpcHelloPayload {
            version: 1,
            flags: 0x0000_00FF,
        };
        let buf = p.encode();
        assert_eq!(buf.len(), AppIpcHelloPayload::WIRE_SIZE);
        let d = AppIpcHelloPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn hello_ok_roundtrip() {
        let token = [0xAA; 16];
        let p = AppIpcHelloOkPayload {
            version: 1,
            client_token: token,
        };
        let buf = p.encode();
        assert_eq!(buf.len(), AppIpcHelloOkPayload::WIRE_SIZE);
        let d = AppIpcHelloOkPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn hello_err_roundtrip() {
        let p = AppIpcHelloErrPayload {
            error_code: ipc_hello_err::VERSION_MISMATCH,
            detail: b"unsupported version 99".to_vec(),
        };
        let buf = p.encode();
        let d = AppIpcHelloErrPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn hello_err_empty_detail() {
        let p = AppIpcHelloErrPayload {
            error_code: ipc_hello_err::SHUTTING_DOWN,
            detail: vec![],
        };
        let buf = p.encode();
        assert_eq!(buf.len(), 4);
        let d = AppIpcHelloErrPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn deliver_roundtrip() {
        let p = AppDeliverPayload {
            src_node_id: [0x01; 32],
            src_app_id: [0u8; 32],
            app_id: [0x02; 32],
            endpoint_id: 5,
            data: veil_bufpool::pooled_shared_from_vec(b"hello veil".to_vec()),
            reply_id: 0,
        };
        let buf = p.encode();
        let d = AppDeliverPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn deliver_reply_id_roundtrips() {
        // The trailing reply_id survives + doesn't disturb the data slice.
        let p = AppDeliverPayload {
            src_node_id: [0x01; 32],
            src_app_id: [0xAA; 32],
            app_id: [0x02; 32],
            endpoint_id: 5,
            data: veil_bufpool::pooled_shared_from_vec(b"reply please".to_vec()),
            reply_id: 0xDEAD_BEEF_0000_0001,
        };
        let d = AppDeliverPayload::decode(&p.encode()).unwrap();
        assert_eq!(d, p);
        assert_eq!(d.reply_id, 0xDEAD_BEEF_0000_0001);
        assert_eq!(d.data.as_ref(), b"reply please");
    }

    #[test]
    fn deliver_empty_data() {
        let p = AppDeliverPayload {
            src_node_id: [0; 32],
            src_app_id: [0u8; 32],
            app_id: [0; 32],
            endpoint_id: 0,
            data: veil_bufpool::pooled_shared_from_vec(vec![]),
            reply_id: 0,
        };
        let d = AppDeliverPayload::decode(&p.encode()).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn ipc_send_roundtrip() {
        let p = AppIpcSendPayload {
            src_app_id: [0u8; 32],
            dst_node_id: [0x10; 32],
            app_id: [0x20; 32],
            endpoint_id: 7,
            require_ack: false,
            anonymous: false,
            anonymous_authenticated: false,
            expect_reply: false,
            is_reply: false,
            reply_id: 0,
            reply_endpoint_id: 0,
            data: veil_bufpool::pooled_shared_from_vec(b"greetings".to_vec()),
        };
        let buf = p.encode();
        let d = AppIpcSendPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn ipc_send_anonymous_authenticated_flag_roundtrips() {
        let p = AppIpcSendPayload {
            src_app_id: [1u8; 32],
            dst_node_id: [0x10; 32],
            app_id: [0x20; 32],
            endpoint_id: 9,
            require_ack: true,
            anonymous: false,
            anonymous_authenticated: true,
            expect_reply: false,
            is_reply: false,
            reply_id: 0,
            reply_endpoint_id: 0,
            data: veil_bufpool::pooled_shared_from_vec(b"authed".to_vec()),
        };
        let d = AppIpcSendPayload::decode(&p.encode()).unwrap();
        assert_eq!(d, p);
        assert!(d.anonymous_authenticated);
        assert!(!d.anonymous);
        // Bit 2 is set in the wire flags word ([100..104] BE).
        let buf = p.encode();
        let flags = u32::from_be_bytes([buf[100], buf[101], buf[102], buf[103]]);
        assert_eq!(
            flags & IPC_SEND_FLAG_ANONYMOUS_AUTHENTICATED,
            IPC_SEND_FLAG_ANONYMOUS_AUTHENTICATED
        );
        assert_eq!(flags & IPC_SEND_FLAG_REQUIRE_ACK, IPC_SEND_FLAG_REQUIRE_ACK);
    }

    #[test]
    fn ipc_send_reply_fields_roundtrip() {
        // expect_reply on an outbound authenticated send.
        let p = AppIpcSendPayload {
            src_app_id: [3u8; 32],
            dst_node_id: [0x10; 32],
            app_id: [0x20; 32],
            endpoint_id: 5,
            require_ack: false,
            anonymous: false,
            anonymous_authenticated: true,
            expect_reply: true,
            is_reply: false,
            reply_id: 0,
            reply_endpoint_id: 77,
            data: veil_bufpool::pooled_shared_from_vec(b"hi".to_vec()),
        };
        let d = AppIpcSendPayload::decode(&p.encode()).unwrap();
        assert_eq!(d, p);
        assert!(d.expect_reply);
        assert_eq!(d.reply_endpoint_id, 77);

        // is_reply carrying an opaque reply_id.
        let r = AppIpcSendPayload {
            src_app_id: [4u8; 32],
            dst_node_id: [0; 32],
            app_id: [0; 32],
            endpoint_id: 0,
            require_ack: false,
            anonymous: false,
            anonymous_authenticated: false,
            expect_reply: false,
            is_reply: true,
            reply_id: 0xDEAD_BEEF_0000_0042,
            reply_endpoint_id: 0,
            data: veil_bufpool::pooled_shared_from_vec(b"pong".to_vec()),
        };
        let d = AppIpcSendPayload::decode(&r.encode()).unwrap();
        assert_eq!(d, r);
        assert!(d.is_reply);
        assert_eq!(d.reply_id, 0xDEAD_BEEF_0000_0042);
    }

    #[test]
    fn ipc_send_decodes_pre_reply_buffer_as_zero() {
        // A pre-reply-channel client encodes no trailing fields. Truncate the
        // 12 trailing bytes off a fresh encode to emulate that wire shape; it
        // must still decode (reply_id/reply_endpoint_id default to 0).
        let p = AppIpcSendPayload {
            src_app_id: [1u8; 32],
            dst_node_id: [2u8; 32],
            app_id: [3u8; 32],
            endpoint_id: 9,
            require_ack: true,
            anonymous: false,
            anonymous_authenticated: false,
            expect_reply: false,
            is_reply: false,
            reply_id: 0,
            reply_endpoint_id: 0,
            data: veil_bufpool::pooled_shared_from_vec(b"legacy".to_vec()),
        };
        let mut buf = p.encode();
        buf.truncate(buf.len() - 12); // drop trailing reply_id + reply_endpoint_id
        let d = AppIpcSendPayload::decode(&buf).unwrap();
        assert_eq!(d.reply_id, 0);
        assert_eq!(d.reply_endpoint_id, 0);
        assert_eq!(&*d.data, b"legacy");
    }

    #[test]
    fn bind_roundtrip() {
        let p = AppBindPayload {
            endpoint_id: 42,
            flags: 0x0001,
            namespace: b"veil.chat".to_vec(),
            name: b"main".to_vec(),
        };
        let buf = p.encode();
        let d = AppBindPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn bind_empty_ns_name() {
        let p = AppBindPayload {
            endpoint_id: 0,
            flags: 0,
            namespace: vec![],
            name: vec![],
        };
        let d = AppBindPayload::decode(&p.encode()).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn bind_ok_roundtrip() {
        let p = AppBindOkPayload {
            app_id: [0xCC; 32],
            endpoint_id: 7,
        };
        let buf = p.encode();
        assert_eq!(buf.len(), AppBindOkPayload::WIRE_SIZE);
        let d = AppBindOkPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn bind_err_roundtrip() {
        let p = AppBindErrPayload {
            error_code: ipc_bind_err::ALREADY_BOUND,
            detail: b"endpoint 7 is in use".to_vec(),
        };
        let buf = p.encode();
        let d = AppBindErrPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn unbind_roundtrip() {
        let p = AppUnbindPayload {
            app_id: [0xAB; 32],
            endpoint_id: 3,
        };
        let buf = p.encode();
        let d = AppUnbindPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn rt_send_roundtrip() {
        let p = AppIpcRtSendPayload {
            dst_node_id: [0x01; 32],
            src_app_id: [0x02; 32],
            dst_app_id: [0x03; 32],
            endpoint_id: 7,
            seq: 42,
            timestamp_us: 1_700_000_000_000_000,
            marker: 0xAB,
            payload_type: 99,
            data: b"hello rt".to_vec(),
        };
        let buf = p.encode();
        assert_eq!(buf.len(), AppIpcRtSendPayload::FIXED_SIZE + p.data.len());
        let d = AppIpcRtSendPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn rt_send_empty_data() {
        let p = AppIpcRtSendPayload {
            dst_node_id: [0; 32],
            src_app_id: [0; 32],
            dst_app_id: [0; 32],
            endpoint_id: 0,
            seq: 0,
            timestamp_us: 0,
            marker: 0,
            payload_type: 0,
            data: vec![],
        };
        let d = AppIpcRtSendPayload::decode(&p.encode()).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn rt_send_too_short() {
        assert!(AppIpcRtSendPayload::decode(&[0u8; 120]).is_err());
    }

    #[test]
    fn hello_too_short() {
        assert!(AppIpcHelloPayload::decode(&[0u8; 3]).is_err());
    }

    #[test]
    fn hello_ok_too_short() {
        assert!(AppIpcHelloOkPayload::decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn hello_err_truncated_detail() {
        // error_code=1, detail_len=10, but only 2 detail bytes
        let mut buf = vec![0, 1, 0, 10, 0xAA, 0xBB];
        let err = AppIpcHelloErrPayload::decode(&buf).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
        // now fix it
        buf.extend_from_slice(&[0; 8]);
        assert!(AppIpcHelloErrPayload::decode(&buf).is_ok());
    }

    #[test]
    fn mobile_background_mode_roundtrip() {
        for mode in [
            MobileBackgroundMode::Foreground,
            MobileBackgroundMode::Active,
            MobileBackgroundMode::LowPower,
        ] {
            let p = SetMobileBackgroundModePayload { mode };
            let buf = p.encode();
            assert_eq!(buf.len(), SetMobileBackgroundModePayload::WIRE_SIZE);
            let d = SetMobileBackgroundModePayload::decode(&buf).unwrap();
            assert_eq!(d, p);
        }
    }

    #[test]
    fn mobile_background_mode_invalid_byte() {
        let err = SetMobileBackgroundModePayload::decode(&[42u8]).unwrap_err();
        assert!(matches!(
            err,
            ProtoError::ValueTooLarge {
                field: "mobile_background_mode",
                ..
            }
        ));
    }

    #[test]
    fn mobile_background_mode_empty_buf() {
        assert!(matches!(
            SetMobileBackgroundModePayload::decode(&[]),
            Err(ProtoError::BufferTooShort { need: 1, got: 0 }),
        ));
    }

    #[test]
    fn mobile_background_mode_pauses_background_only_for_lowpower() {
        assert!(!MobileBackgroundMode::Foreground.pauses_background_work());
        assert!(!MobileBackgroundMode::Active.pauses_background_work());
        assert!(MobileBackgroundMode::LowPower.pauses_background_work());
    }

    #[test]
    fn network_changed_roundtrip() {
        for kind in [
            NetworkKind::Offline,
            NetworkKind::Wifi,
            NetworkKind::Cellular,
            NetworkKind::Ethernet,
            NetworkKind::Unknown,
        ] {
            let p = NetworkChangedPayload {
                kind,
                mtu_hint: 1280,
            };
            let buf = p.encode();
            assert_eq!(buf.len(), NetworkChangedPayload::WIRE_SIZE);
            let d = NetworkChangedPayload::decode(&buf).unwrap();
            assert_eq!(d, p);
        }
    }

    #[test]
    fn network_kind_unknown_byte_round_trips_as_unknown() {
        // Forward-compatibility: a byte we don't recognise decodes to Unknown
        // rather than panicking — older clients can stay running when the
        // app driver introduces a new network classification.
        let buf = vec![99u8, 0, 0, 0, 0, 0, 0];
        let d = NetworkChangedPayload::decode(&buf).unwrap();
        assert_eq!(d.kind, NetworkKind::Unknown);
    }

    #[test]
    fn network_changed_too_short() {
        assert!(matches!(
            NetworkChangedPayload::decode(&[0u8; 6]),
            Err(ProtoError::BufferTooShort { need: 7, got: 6 }),
        ));
    }

    #[test]
    fn node_identity_roundtrip_ed25519_size() {
        // Typical Ed25519 public key = 32 bytes.
        let p = NodeIdentityPayload {
            node_id: [42u8; 32],
            algo: 0,
            public_key: vec![0xAB; 32],
            relay_x25519_pubkey: None,
        };
        let buf = p.encode();
        // FIXED_SIZE + 32 (pubkey) + 1 (trailer flag = 0).
        assert_eq!(buf.len(), NodeIdentityPayload::FIXED_SIZE + 32 + 1);
        let d = NodeIdentityPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn node_identity_roundtrip_falcon_size() {
        // Falcon-512 public key ≈ 897 bytes.
        let p = NodeIdentityPayload {
            node_id: [99u8; 32],
            algo: 1,
            public_key: vec![0xCD; 897],
            relay_x25519_pubkey: None,
        };
        let buf = p.encode();
        let d = NodeIdentityPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn node_identity_roundtrip_empty_pubkey() {
        // Defensive: zero-length pubkey decode should round-trip
        // (won't happen on the wire — daemon always populates — but
        // we don't want decode to panic on a malformed app payload).
        let p = NodeIdentityPayload {
            node_id: [0u8; 32],
            algo: 0,
            public_key: vec![],
            relay_x25519_pubkey: None,
        };
        let buf = p.encode();
        let d = NodeIdentityPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn node_identity_too_short() {
        assert!(matches!(
            NodeIdentityPayload::decode(&[0u8; 34]),
            Err(ProtoError::BufferTooShort { need: 35, got: 34 }),
        ));
    }

    #[test]
    fn node_identity_truncated_pubkey() {
        // Header claims 100-byte pubkey but only 50 bytes follow.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]); // node_id
        buf.push(0); // algo
        buf.extend_from_slice(&100u16.to_be_bytes()); // claimed pubkey_len
        buf.extend_from_slice(&[0u8; 50]); // truncated
        assert!(matches!(
            NodeIdentityPayload::decode(&buf),
            Err(ProtoError::BufferTooShort { need: 135, got: 85 }),
        ));
    }

    #[test]
    fn t1_4_p0_node_identity_with_relay_x25519_round_trip() {
        let p = NodeIdentityPayload {
            node_id: [7u8; 32],
            algo: 0,
            public_key: vec![0xAB; 32],
            relay_x25519_pubkey: Some([0xEE; 32]),
        };
        let buf = p.encode();
        // FIXED_SIZE + 32 (pubkey) + 1 (flag) + 32 (relay pk).
        assert_eq!(buf.len(), NodeIdentityPayload::FIXED_SIZE + 32 + 1 + 32);
        let d = NodeIdentityPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
        assert_eq!(d.relay_x25519_pubkey, Some([0xEE; 32]));
    }

    #[test]
    fn t1_4_p0_node_identity_legacy_buffer_decodes_with_none() {
        // Old daemon (pre-T1.4) encoded only [node_id || algo || len || pubkey]
        // with no trailer at all. New decoder must accept it and yield None.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[1u8; 32]); // node_id
        buf.push(0); // algo
        buf.extend_from_slice(&32u16.to_be_bytes()); // pubkey_len
        buf.extend_from_slice(&[0xAB; 32]); // pubkey
        // NO trailer byte — strictly the legacy format.
        let d = NodeIdentityPayload::decode(&buf).unwrap();
        assert_eq!(d.relay_x25519_pubkey, None);
        assert_eq!(d.public_key, vec![0xAB; 32]);
    }

    #[test]
    fn t1_4_p0_node_identity_relay_flag_present_but_truncated() {
        // Trailer claims relay_x25519 present but only 10 of 32 bytes follow.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0);
        buf.extend_from_slice(&32u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 32]); // pubkey
        buf.push(1); // flag = present
        buf.extend_from_slice(&[0xEE; 10]); // truncated
        assert!(matches!(
            NodeIdentityPayload::decode(&buf),
            Err(ProtoError::BufferTooShort { .. }),
        ));
    }

    #[test]
    fn t1_4_p0_node_identity_relay_flag_invalid_byte_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0);
        buf.extend_from_slice(&32u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(99); // invalid flag (only 0 or 1 allowed)
        assert!(matches!(
            NodeIdentityPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "node_identity.relay_x25519_present",
                ..
            }),
        ));
    }

    #[test]
    fn node_identity_oversized_pubkey_rejected() {
        // Header claims pubkey > MAX_NODE_IDENTITY_PUBKEY_LEN.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0);
        let oversized = (MAX_NODE_IDENTITY_PUBKEY_LEN + 1) as u16;
        buf.extend_from_slice(&oversized.to_be_bytes());
        // Don't bother appending payload — decoder rejects at length check.
        assert!(matches!(
            NodeIdentityPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "node_identity.public_key_len",
                ..
            }),
        ));
    }

    // ── Mailbox put/fetch/ack ─────────────────────────

    #[test]
    fn t1_4_p2_mailbox_put_round_trip() {
        let p = MailboxPutPayload {
            receiver_id: [1u8; 32],
            content_id: [2u8; 32],
            sender_id: [3u8; 32],
            blob: vec![0xAB; 1024],
            push_envelope: None,
            capability_token: None,
            wake_hmac_envelope: None,
        };
        let buf = p.encode();
        // encoder emits three trailer
        // length-prefix u16s (env_len + cap_token_len + wake_hmac_env_len,
        // all zero here) — total = HEADER_SIZE + blob + 2 + 2 + 2.
        // (Trailer 3 = wake_hmac_envelope added in slice 4.3.4 follow-up.)
        assert_eq!(buf.len(), MailboxPutPayload::HEADER_SIZE + 1024 + 2 + 2 + 2);
        let d = MailboxPutPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p2_mailbox_put_empty_blob_round_trip() {
        let p = MailboxPutPayload {
            receiver_id: [9u8; 32],
            content_id: [9u8; 32],
            sender_id: [9u8; 32],
            blob: vec![],
            push_envelope: None,
            capability_token: None,
            wake_hmac_envelope: None,
        };
        let buf = p.encode();
        let d = MailboxPutPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p3_mailbox_put_with_envelope_round_trip() {
        let p = MailboxPutPayload {
            receiver_id: [1u8; 32],
            content_id: [2u8; 32],
            sender_id: [3u8; 32],
            blob: vec![0xAB; 256],
            push_envelope: Some(vec![0xEE; 60]),
            capability_token: None,
            wake_hmac_envelope: None,
        };
        let buf = p.encode();
        let d = MailboxPutPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
        assert_eq!(d.push_envelope, Some(vec![0xEE; 60]));
    }

    // ── Trailer 3: wake_hmac_envelope (Epic 489.10 slice 4.3.4 follow-up) ──

    #[test]
    fn epic489_10_mailbox_put_with_wake_hmac_envelope_round_trip() {
        let p = MailboxPutPayload {
            receiver_id: [1u8; 32],
            content_id: [2u8; 32],
            sender_id: [3u8; 32],
            blob: vec![0xAB; 256],
            push_envelope: Some(vec![0xEE; 60]),
            capability_token: Some(vec![0xCC; 100]),
            wake_hmac_envelope: Some(vec![0xBB; 92]),
        };
        let buf = p.encode();
        let d = MailboxPutPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
        assert_eq!(d.wake_hmac_envelope, Some(vec![0xBB; 92]));
    }

    #[test]
    fn epic489_10_mailbox_put_legacy_2_trailer_decodes_under_new_decoder() {
        // Construct a wire blob manually using ONLY the v2 two-trailer
        // layout (no Trailer 3 bytes) — confirms backward-compat decode
        // yields wake_hmac_envelope = None.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[1u8; 32]);
        buf.extend_from_slice(&[2u8; 32]);
        buf.extend_from_slice(&[3u8; 32]);
        buf.extend_from_slice(&(0u32).to_be_bytes()); // blob_len = 0
        buf.extend_from_slice(&(0u16).to_be_bytes()); // Trailer 1: push_envelope_len = 0
        buf.extend_from_slice(&(0u16).to_be_bytes()); // Trailer 2: cap_token_len = 0
        // No Trailer 3 bytes — old-style 2-trailer wire.
        let d = MailboxPutPayload::decode(&buf).unwrap();
        assert!(d.wake_hmac_envelope.is_none());
    }

    #[test]
    fn epic489_10_mailbox_put_wake_hmac_envelope_oversized_at_decode() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&(0u32).to_be_bytes());
        buf.extend_from_slice(&(0u16).to_be_bytes());
        buf.extend_from_slice(&(0u16).to_be_bytes());
        let bad_len = (MAX_WAKE_HMAC_ENVELOPE_BYTES + 1) as u16;
        buf.extend_from_slice(&bad_len.to_be_bytes());
        buf.extend(std::iter::repeat_n(0u8, MAX_WAKE_HMAC_ENVELOPE_BYTES + 1));
        let err = MailboxPutPayload::decode(&buf).unwrap_err();
        assert!(matches!(err, ProtoError::ValueTooLarge { .. }));
    }

    #[test]
    fn phase650b_316_mailbox_put_with_capability_token_round_trip() {
        let p = MailboxPutPayload {
            receiver_id: [1u8; 32],
            content_id: [2u8; 32],
            sender_id: [3u8; 32],
            blob: vec![0xAB; 256],
            push_envelope: Some(vec![0xEE; 60]),
            capability_token: Some(vec![0xCC; 128]),
            wake_hmac_envelope: None,
        };
        let buf = p.encode();
        let d = MailboxPutPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
        assert_eq!(d.capability_token, Some(vec![0xCC; 128]));
    }

    #[test]
    fn phase650b_316_mailbox_put_with_token_no_envelope() {
        // Token attached but no push envelope — still must round-trip
        // confirms the cap_token trailer doesn't depend on envelope being
        // present.
        let p = MailboxPutPayload {
            receiver_id: [1u8; 32],
            content_id: [2u8; 32],
            sender_id: [3u8; 32],
            blob: vec![0xAB; 100],
            push_envelope: None,
            capability_token: Some(vec![0xCC; 64]),
            wake_hmac_envelope: None,
        };
        let buf = p.encode();
        let d = MailboxPutPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn phase650b_316_mailbox_put_legacy_buffer_decodes_with_no_token() {
        // Pre-slice-1 sender emits header+blob+env_trailer but no
        // cap_token trailer. New decoder must produce capability_token=None.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[1u8; 32]);
        buf.extend_from_slice(&[2u8; 32]);
        buf.extend_from_slice(&[3u8; 32]);
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(b"hello");
        buf.extend_from_slice(&0u16.to_be_bytes()); // env_len = 0
        // No cap_token trailer.
        let d = MailboxPutPayload::decode(&buf).unwrap();
        assert_eq!(d.blob, b"hello");
        assert_eq!(d.push_envelope, None);
        assert_eq!(d.capability_token, None);
    }

    #[test]
    fn phase650b_316_mailbox_put_cap_token_too_large_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[1u8; 32]);
        buf.extend_from_slice(&[2u8; 32]);
        buf.extend_from_slice(&[3u8; 32]);
        buf.extend_from_slice(&0u32.to_be_bytes()); // blob_len = 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // env_len = 0
        // cap_token_len > MAX_MAILBOX_CAPABILITY_TOKEN_BYTES.
        buf.extend_from_slice(&((MAX_MAILBOX_CAPABILITY_TOKEN_BYTES + 1) as u16).to_be_bytes());
        let err = MailboxPutPayload::decode(&buf).unwrap_err();
        assert!(matches!(
            err,
            ProtoError::ValueTooLarge {
                field: "mailbox_put.cap_token_len",
                ..
            }
        ));
    }

    #[test]
    fn t1_4_p3_mailbox_put_legacy_buffer_decodes_with_no_envelope() {
        // Old sender (pre-T1.4 P3) emits header+blob, no trailer.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]); // receiver
        buf.extend_from_slice(&[0u8; 32]); // content
        buf.extend_from_slice(&[0u8; 32]); // sender
        buf.extend_from_slice(&5u32.to_be_bytes()); // blob_len = 5
        buf.extend_from_slice(b"hello");
        // No trailer.
        let d = MailboxPutPayload::decode(&buf).unwrap();
        assert_eq!(d.push_envelope, None);
        assert_eq!(d.blob, b"hello");
    }

    #[test]
    fn t1_4_p3_mailbox_put_oversized_envelope_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]); // receiver
        buf.extend_from_slice(&[0u8; 32]); // content
        buf.extend_from_slice(&[0u8; 32]); // sender
        buf.extend_from_slice(&0u32.to_be_bytes()); // blob_len = 0
        let oversized = (MAX_PUSH_ENVELOPE_BYTES + 1) as u16;
        buf.extend_from_slice(&oversized.to_be_bytes());
        assert!(matches!(
            MailboxPutPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "mailbox_put.push_envelope_len",
                ..
            }),
        ));
    }

    #[test]
    fn t1_4_p3_mailbox_put_truncated_envelope_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]); // receiver
        buf.extend_from_slice(&[0u8; 32]); // content
        buf.extend_from_slice(&[0u8; 32]); // sender
        buf.extend_from_slice(&0u32.to_be_bytes()); // blob_len = 0
        buf.extend_from_slice(&100u16.to_be_bytes()); // env_len = 100
        buf.extend_from_slice(&[0u8; 50]); // only 50 bytes
        assert!(matches!(
            MailboxPutPayload::decode(&buf),
            Err(ProtoError::BufferTooShort { .. }),
        ));
    }

    #[test]
    fn t1_4_p2_mailbox_put_oversized_blob_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0u8; 32]);
        let oversized = (MAX_MAILBOX_BLOB_BYTES + 1) as u32;
        buf.extend_from_slice(&oversized.to_be_bytes());
        assert!(matches!(
            MailboxPutPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "mailbox_put.blob_len",
                ..
            }),
        ));
    }

    #[test]
    fn t1_4_p2_mailbox_put_too_short_rejected() {
        assert!(matches!(
            MailboxPutPayload::decode(&[0u8; 50]),
            Err(ProtoError::BufferTooShort { need: 100, .. }),
        ));
    }

    #[test]
    fn t1_4_p2_mailbox_put_truncated_blob_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 96]); // receiver+content+sender
        buf.extend_from_slice(&100u32.to_be_bytes()); // claims 100 bytes
        buf.extend_from_slice(&[0u8; 50]); // only 50
        assert!(matches!(
            MailboxPutPayload::decode(&buf),
            Err(ProtoError::BufferTooShort { .. }),
        ));
    }

    #[test]
    fn t1_4_p2_mailbox_put_ok_round_trip_all_statuses() {
        for status in [
            MailboxPutStatus::Stored,
            MailboxPutStatus::Duplicate,
            MailboxPutStatus::QuotaPerReceiverExceeded,
            MailboxPutStatus::QuotaGlobalExceeded,
            MailboxPutStatus::RateLimited,
            MailboxPutStatus::NotMailboxRelay,
        ] {
            let p = MailboxPutOkPayload { status, evicted: 7 };
            let buf = p.encode();
            assert_eq!(buf.len(), MailboxPutOkPayload::WIRE_SIZE);
            let d = MailboxPutOkPayload::decode(&buf).unwrap();
            assert_eq!(d, p);
        }
    }

    #[test]
    fn t1_4_p2_mailbox_put_ok_unknown_status_rejected() {
        let buf = [99u8, 0, 0, 0, 0];
        assert!(matches!(
            MailboxPutOkPayload::decode(&buf),
            Err(ProtoError::Malformed(_)),
        ));
    }

    #[test]
    fn t1_4_p2_mailbox_fetch_round_trip() {
        let p = MailboxFetchPayload {
            receiver_id: [7u8; 32],
            auth_cookie: [0xCC; MAILBOX_AUTH_COOKIE_LEN],
        };
        let buf = p.encode();
        assert_eq!(buf.len(), MailboxFetchPayload::WIRE_SIZE);
        let d = MailboxFetchPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p2_mailbox_fetch_resp_empty_round_trip() {
        let p = MailboxFetchRespPayload { blobs: vec![] };
        let buf = p.encode();
        assert_eq!(buf.len(), 2);
        let d = MailboxFetchRespPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p2_mailbox_fetch_resp_multi_round_trip() {
        let p = MailboxFetchRespPayload {
            blobs: vec![
                MailboxBlobWire {
                    sender_id: [1u8; 32],
                    content_id: [2u8; 32],
                    deposited_at: 1_700_000_000,
                    blob: b"first-blob".to_vec(),
                },
                MailboxBlobWire {
                    sender_id: [3u8; 32],
                    content_id: [4u8; 32],
                    deposited_at: 1_700_000_500,
                    blob: vec![0xEE; 4096],
                },
            ],
        };
        let buf = p.encode();
        let d = MailboxFetchRespPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p2_mailbox_fetch_resp_oversized_count_rejected() {
        let mut buf = Vec::new();
        let too_many = (MAX_MAILBOX_FETCH_ENTRIES + 1) as u16;
        buf.extend_from_slice(&too_many.to_be_bytes());
        assert!(matches!(
            MailboxFetchRespPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "mailbox_fetch_resp.count",
                ..
            }),
        ));
    }

    #[test]
    fn t1_4_p2_mailbox_fetch_resp_truncated_entry_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes()); // count = 1
        buf.extend_from_slice(&[0u8; 30]); // truncated entry header
        assert!(matches!(
            MailboxFetchRespPayload::decode(&buf),
            Err(ProtoError::BufferTooShort { .. }),
        ));
    }

    #[test]
    fn t1_4_p2_mailbox_ack_round_trip() {
        let p = MailboxAckPayload {
            receiver_id: [11u8; 32],
            content_id: [22u8; 32],
            auth_cookie: [0xAA; MAILBOX_AUTH_COOKIE_LEN],
        };
        let buf = p.encode();
        assert_eq!(buf.len(), MailboxAckPayload::WIRE_SIZE);
        let d = MailboxAckPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p2_mailbox_ack_too_short_rejected() {
        assert!(matches!(
            MailboxAckPayload::decode(&[0u8; 70]),
            Err(ProtoError::BufferTooShort { need: 80, .. }),
        ));
    }

    // ── Outbox put/find-missing/ack ────────────────────

    #[test]
    fn t1_4_p4_outbox_put_round_trip() {
        let p = OutboxPutPayload {
            receiver_id: [1u8; 32],
            content_id: [2u8; 32],
            blob: vec![0xAB; 256],
        };
        let buf = p.encode();
        assert_eq!(buf.len(), OutboxPutPayload::HEADER_SIZE + 256);
        let d = OutboxPutPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p4_outbox_put_oversized_blob_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 64]);
        let oversized = (MAX_MAILBOX_BLOB_BYTES + 1) as u32;
        buf.extend_from_slice(&oversized.to_be_bytes());
        assert!(matches!(
            OutboxPutPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "outbox_put.blob_len",
                ..
            }),
        ));
    }

    #[test]
    fn t1_4_p4_outbox_find_missing_round_trip() {
        let p = OutboxFindMissingPayload {
            receiver_id: [7u8; 32],
            since: 1_700_000_000,
            bloom: vec![0xEE; 1024],
        };
        let buf = p.encode();
        assert_eq!(buf.len(), OutboxFindMissingPayload::HEADER_SIZE + 1024);
        let d = OutboxFindMissingPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p4_outbox_find_missing_oversized_bloom_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]); // receiver
        buf.extend_from_slice(&0u64.to_be_bytes()); // since
        let oversized = (MAX_OUTBOX_BLOOM_BYTES + 1) as u32;
        buf.extend_from_slice(&oversized.to_be_bytes());
        assert!(matches!(
            OutboxFindMissingPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "outbox_find_missing.bloom_len",
                ..
            }),
        ));
    }

    #[test]
    fn t1_4_p4_outbox_find_missing_resp_empty_round_trip() {
        let p = OutboxFindMissingRespPayload { entries: vec![] };
        let buf = p.encode();
        assert_eq!(buf.len(), 2);
        let d = OutboxFindMissingRespPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p4_outbox_find_missing_resp_multi_round_trip() {
        let p = OutboxFindMissingRespPayload {
            entries: vec![
                OutboxEntryWire {
                    content_id: [1u8; 32],
                    deposited_at: 100,
                    blob: b"first".to_vec(),
                },
                OutboxEntryWire {
                    content_id: [2u8; 32],
                    deposited_at: 200,
                    blob: vec![0xCD; 4096],
                },
            ],
        };
        let buf = p.encode();
        let d = OutboxFindMissingRespPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p4_outbox_find_missing_resp_oversized_count_rejected() {
        let mut buf = Vec::new();
        let too_many = (MAX_OUTBOX_FIND_MISSING_ENTRIES + 1) as u16;
        buf.extend_from_slice(&too_many.to_be_bytes());
        assert!(matches!(
            OutboxFindMissingRespPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "outbox_find_missing_resp.count",
                ..
            }),
        ));
    }

    #[test]
    fn t1_4_p4_outbox_ack_round_trip() {
        let p = OutboxAckPayload {
            receiver_id: [11u8; 32],
            content_id: [22u8; 32],
        };
        let buf = p.encode();
        assert_eq!(buf.len(), OutboxAckPayload::WIRE_SIZE);
        let d = OutboxAckPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p4_outbox_ack_too_short_rejected() {
        assert!(matches!(
            OutboxAckPayload::decode(&[0u8; 50]),
            Err(ProtoError::BufferTooShort { need: 64, .. }),
        ));
    }

    // ── Lookup rendezvous replicas ────────────────────

    #[test]
    fn t1_4_p5c_lookup_replicas_request_round_trip() {
        let p = LookupRendezvousReplicasPayload {
            receiver_id: [7u8; 32],
            max_replicas: 3,
        };
        let buf = p.encode();
        assert_eq!(buf.len(), LookupRendezvousReplicasPayload::WIRE_SIZE);
        let d = LookupRendezvousReplicasPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p5c_lookup_replicas_too_short_rejected() {
        assert!(matches!(
            LookupRendezvousReplicasPayload::decode(&[0u8; 32]),
            Err(ProtoError::BufferTooShort { need: 33, .. }),
        ));
    }

    #[test]
    fn t1_4_p5c_replica_wire_round_trip_with_envelope() {
        let r = ReplicaWire {
            relay_node_id: [11u8; 32],
            valid_until_unix: 1_700_000_000,
            push_envelope: vec![0xEE; 60],
            capability_token: vec![],
            wake_hmac_envelope: vec![],
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: vec![],
        };
        let mut buf = Vec::new();
        r.encode_to(&mut buf);
        let (d, end) = ReplicaWire::decode_from(&buf, 0).unwrap();
        assert_eq!(d, r);
        assert_eq!(end, buf.len());
    }

    #[test]
    fn t489_10_2b_replica_wire_round_trip_with_wake_hmac() {
        // Round-trip an entry carrying ALL THREE non-empty trailers:
        // push_envelope, capability_token and the new wake_hmac_envelope.
        let r = ReplicaWire {
            relay_node_id: [11u8; 32],
            valid_until_unix: 1_700_000_000,
            push_envelope: vec![0xEE; 60],
            capability_token: vec![0xAB; 40],
            wake_hmac_envelope: vec![0x5A; MAX_WAKE_HMAC_ENVELOPE_BYTES],
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: vec![],
        };
        let mut buf = Vec::new();
        r.encode_to(&mut buf);
        let (d, end) = ReplicaWire::decode_from(&buf, 0).unwrap();
        assert_eq!(d, r);
        assert_eq!(
            d.wake_hmac_envelope,
            vec![0x5A; MAX_WAKE_HMAC_ENVELOPE_BYTES]
        );
        // Consumed length must cover all three trailers (== full buffer).
        assert_eq!(end, buf.len());
    }

    #[test]
    fn t489_10_2b_replica_wire_decode_backward_compat_no_wake_trailer() {
        // Hand-craft a 2-trailer buffer exactly as a pre-slice-2b encoder
        // would: relay_node_id | valid_until | env_len+env | cap_len+cap,
        // and NOTHING after the cap_token trailer. A new decoder must default
        // `wake_hmac_envelope == []` and report consumed length == buf.len()
        // (the entry boundary, so the multi-replica walker advances right).
        let mut buf = Vec::new();
        buf.extend_from_slice(&[7u8; 32]); // relay_node_id
        buf.extend_from_slice(&1_234u64.to_be_bytes()); // valid_until
        buf.extend_from_slice(&3u16.to_be_bytes()); // env_len
        buf.extend_from_slice(&[0x11, 0x22, 0x33]); // push_envelope
        buf.extend_from_slice(&2u16.to_be_bytes()); // cap_len
        buf.extend_from_slice(&[0x44, 0x55]); // capability_token
        let len_before = buf.len();
        let (d, end) = ReplicaWire::decode_from(&buf, 0).unwrap();
        assert_eq!(d.relay_node_id, [7u8; 32]);
        assert_eq!(d.valid_until_unix, 1_234);
        assert_eq!(d.push_envelope, vec![0x11, 0x22, 0x33]);
        assert_eq!(d.capability_token, vec![0x44, 0x55]);
        assert_eq!(d.wake_hmac_envelope, Vec::<u8>::new());
        assert_eq!(end, len_before);
    }

    #[test]
    fn t489_10_2b_replica_wire_oversized_wake_hmac_rejected() {
        // Full valid prefix (relay|valid|env|cap) then a wake_len that
        // exceeds MAX_WAKE_HMAC_ENVELOPE_BYTES — must be rejected at decode.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]); // relay_node_id
        buf.extend_from_slice(&0u64.to_be_bytes()); // valid_until
        buf.extend_from_slice(&0u16.to_be_bytes()); // env_len = 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // cap_len = 0
        let oversized = (MAX_WAKE_HMAC_ENVELOPE_BYTES + 1) as u16;
        buf.extend_from_slice(&oversized.to_be_bytes()); // wake_len (bad)
        buf.extend(std::iter::repeat_n(0u8, MAX_WAKE_HMAC_ENVELOPE_BYTES + 1));
        assert!(matches!(
            ReplicaWire::decode_from(&buf, 0),
            Err(ProtoError::ValueTooLarge {
                field: "replica_wire.wake_hmac_envelope_len",
                ..
            }),
        ));
    }

    #[test]
    fn t489_10_2b_replicas_resp_multi_round_trip_distinct_wake_hmac() {
        // Two entries each carrying a DIFFERENT wake_hmac_envelope (one short,
        // one max-length, one empty) prove the container's offset-walking
        // accounts for the variable-length 3rd trailer per entry.
        let p = LookupRendezvousReplicasRespPayload {
            entries: vec![
                ReplicaWire {
                    relay_node_id: [1u8; 32],
                    valid_until_unix: 100,
                    push_envelope: vec![0xAA; 32],
                    capability_token: vec![0x01; 8],
                    wake_hmac_envelope: vec![0xB1; 16],
                    rendezvous_kem_algo: 0,
                    rendezvous_kem_pk: vec![],
                },
                ReplicaWire {
                    relay_node_id: [2u8; 32],
                    valid_until_unix: 200,
                    push_envelope: vec![],
                    capability_token: vec![],
                    wake_hmac_envelope: vec![0xB2; MAX_WAKE_HMAC_ENVELOPE_BYTES],
                    rendezvous_kem_algo: 0,
                    rendezvous_kem_pk: vec![],
                },
                ReplicaWire {
                    relay_node_id: [3u8; 32],
                    valid_until_unix: 300,
                    push_envelope: vec![0xCC; 60],
                    capability_token: vec![0x03; 4],
                    wake_hmac_envelope: vec![],
                    rendezvous_kem_algo: 0,
                    rendezvous_kem_pk: vec![],
                },
            ],
        };
        let buf = p.encode();
        let d = LookupRendezvousReplicasRespPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
        assert_eq!(d.entries[0].wake_hmac_envelope, vec![0xB1; 16]);
        assert_eq!(
            d.entries[1].wake_hmac_envelope,
            vec![0xB2; MAX_WAKE_HMAC_ENVELOPE_BYTES]
        );
        assert_eq!(d.entries[2].wake_hmac_envelope, Vec::<u8>::new());
    }

    #[test]
    fn t1_4_p5c_replica_wire_round_trip_empty_envelope() {
        let r = ReplicaWire {
            relay_node_id: [22u8; 32],
            valid_until_unix: 0,
            push_envelope: vec![],
            capability_token: vec![],
            wake_hmac_envelope: vec![],
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: vec![],
        };
        let mut buf = Vec::new();
        r.encode_to(&mut buf);
        let (d, _end) = ReplicaWire::decode_from(&buf, 0).unwrap();
        assert_eq!(d, r);
    }

    #[test]
    fn t1_4_p5c_replicas_resp_empty_round_trip() {
        let p = LookupRendezvousReplicasRespPayload { entries: vec![] };
        let buf = p.encode();
        assert_eq!(buf.len(), 1);
        let d = LookupRendezvousReplicasRespPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p5c_replicas_resp_multi_round_trip() {
        let p = LookupRendezvousReplicasRespPayload {
            entries: vec![
                ReplicaWire {
                    relay_node_id: [1u8; 32],
                    valid_until_unix: 100,
                    push_envelope: vec![0xAA; 32],
                    capability_token: vec![],
                    wake_hmac_envelope: vec![],
                    rendezvous_kem_algo: 0,
                    rendezvous_kem_pk: vec![],
                },
                ReplicaWire {
                    relay_node_id: [2u8; 32],
                    valid_until_unix: 200,
                    push_envelope: vec![],
                    capability_token: vec![],
                    wake_hmac_envelope: vec![],
                    rendezvous_kem_algo: 0,
                    rendezvous_kem_pk: vec![],
                },
                ReplicaWire {
                    relay_node_id: [3u8; 32],
                    valid_until_unix: 300,
                    push_envelope: vec![0xCC; 60],
                    capability_token: vec![],
                    wake_hmac_envelope: vec![],
                    rendezvous_kem_algo: 0,
                    rendezvous_kem_pk: vec![],
                },
            ],
        };
        let buf = p.encode();
        let d = LookupRendezvousReplicasRespPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn t1_4_p5c_replicas_resp_oversized_count_rejected() {
        let buf = vec![(MAX_RENDEZVOUS_REPLICAS + 1) as u8];
        assert!(matches!(
            LookupRendezvousReplicasRespPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "lookup_rendezvous_replicas_resp.count",
                ..
            }),
        ));
    }

    #[test]
    fn t1_4_p5c_replica_wire_oversized_envelope_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 32]); // relay
        buf.extend_from_slice(&0u64.to_be_bytes()); // valid_until
        let oversized = (MAX_PUSH_ENVELOPE_BYTES + 1) as u16;
        buf.extend_from_slice(&oversized.to_be_bytes());
        assert!(matches!(
            ReplicaWire::decode_from(&buf, 0),
            Err(ProtoError::ValueTooLarge {
                field: "replica_wire.envelope_len",
                ..
            }),
        ));
    }

    #[test]
    fn peers_list_roundtrip_empty() {
        let p = PeersListPayload { peers: vec![] };
        let buf = p.encode();
        assert_eq!(buf.len(), 2);
        let d = PeersListPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn peers_list_roundtrip_typical() {
        let p = PeersListPayload {
            peers: vec![
                PeersListEntry {
                    node_id: [1u8; 32],
                    state: peer_state::ACTIVE,
                    direction: peer_direction::OUTBOUND,
                    transport: b"tcp://1.2.3.4:5555".to_vec(),
                },
                PeersListEntry {
                    node_id: [2u8; 32],
                    state: peer_state::CONNECTING,
                    direction: peer_direction::INBOUND,
                    transport: b"tcp://10.0.0.1:5555".to_vec(),
                },
            ],
        };
        let buf = p.encode();
        let d = PeersListPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn peers_list_roundtrip_empty_transport() {
        let p = PeersListPayload {
            peers: vec![PeersListEntry {
                node_id: [9u8; 32],
                state: peer_state::ACTIVE,
                direction: peer_direction::OUTBOUND,
                transport: vec![], // matched-without-known-transport edge case
            }],
        };
        let buf = p.encode();
        let d = PeersListPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn peers_list_too_short() {
        assert!(matches!(
            PeersListPayload::decode(&[0u8; 1]),
            Err(ProtoError::BufferTooShort { need: 2, got: 1 }),
        ));
    }

    #[test]
    fn peers_list_count_overflow_rejected() {
        let mut buf = Vec::new();
        let oversized = (MAX_PEERS_LIST_ENTRIES + 1) as u16;
        buf.extend_from_slice(&oversized.to_be_bytes());
        assert!(matches!(
            PeersListPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "peers_list.count",
                ..
            }),
        ));
    }

    #[test]
    fn peers_list_truncated_after_header() {
        // count=1 declared but only enough bytes for the count itself.
        let buf = vec![0u8, 1];
        let err = PeersListPayload::decode(&buf).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn peers_list_oversized_transport_rejected() {
        // Single entry with claimed transport_len > MAX_PEER_TRANSPORT_LEN.
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes()); // count
        buf.extend_from_slice(&[0u8; 32]); // node_id
        buf.push(0); // state
        buf.push(0); // direction
        let oversized = (MAX_PEER_TRANSPORT_LEN + 1) as u16;
        buf.extend_from_slice(&oversized.to_be_bytes());
        assert!(matches!(
            PeersListPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "peer_entry.transport_len",
                ..
            }),
        ));
    }

    #[test]
    fn peers_list_at_cap_roundtrips() {
        let p = PeersListPayload {
            peers: (0..MAX_PEERS_LIST_ENTRIES)
                .map(|i| PeersListEntry {
                    node_id: [i as u8; 32],
                    state: peer_state::ACTIVE,
                    direction: peer_direction::OUTBOUND,
                    transport: format!("tcp://10.0.0.{}:5555", i % 255).into_bytes(),
                })
                .collect(),
        };
        let buf = p.encode();
        let d = PeersListPayload::decode(&buf).unwrap();
        assert_eq!(d.peers.len(), MAX_PEERS_LIST_ENTRIES);
        assert_eq!(d, p);
    }

    #[test]
    fn join_bootstrap_roundtrip_plain() {
        let p = JoinBootstrapPayload {
            uri: "veil:bootstrap?pk=aaa&t=tcp://1.2.3.4:5555&a=ed25519&nc=bbb".into(),
            password: None,
            expected_issuer_pk: None,
        };
        let buf = p.encode();
        let d = JoinBootstrapPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn join_bootstrap_roundtrip_encrypted() {
        let p = JoinBootstrapPayload {
            uri: "veil:pair?b=base64ciphertext".into(),
            password: Some("hunter2".into()),
            expected_issuer_pk: None,
        };
        let buf = p.encode();
        let d = JoinBootstrapPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn join_bootstrap_roundtrip_signed() {
        let p = JoinBootstrapPayload {
            uri: "veil:signed-invite?b=base64".into(),
            password: None,
            expected_issuer_pk: Some("base64issuerpk".into()),
        };
        let buf = p.encode();
        let d = JoinBootstrapPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn join_bootstrap_too_short_no_uri_len() {
        assert!(matches!(
            JoinBootstrapPayload::decode(&[0u8; 1]),
            Err(ProtoError::BufferTooShort { need: 2, got: 1 }),
        ));
    }

    #[test]
    fn join_bootstrap_oversized_uri_rejected() {
        let mut buf = Vec::new();
        let oversized = (MAX_JOIN_URI_LEN + 1) as u16;
        buf.extend_from_slice(&oversized.to_be_bytes());
        assert!(matches!(
            JoinBootstrapPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "join_bootstrap.uri_len",
                ..
            }),
        ));
    }

    #[test]
    fn join_bootstrap_invalid_utf8_uri() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u16.to_be_bytes());
        buf.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // non-UTF-8
        buf.extend_from_slice(&0u16.to_be_bytes()); // password_len
        buf.extend_from_slice(&0u16.to_be_bytes()); // issuer_pk_len
        assert!(matches!(
            JoinBootstrapPayload::decode(&buf),
            Err(ProtoError::InvalidUtf8),
        ));
    }

    #[test]
    fn join_result_roundtrip_ok() {
        let p = JoinBootstrapResultPayload {
            status: join_status::OK,
            peer_node_id: [0xAB; 32],
            detail: b"connecting".to_vec(),
        };
        let buf = p.encode();
        let d = JoinBootstrapResultPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn join_result_roundtrip_password_required() {
        let p = JoinBootstrapResultPayload {
            status: join_status::PASSWORD_REQUIRED,
            peer_node_id: [0u8; 32],
            detail: b"URI is encrypted; pass password".to_vec(),
        };
        let buf = p.encode();
        let d = JoinBootstrapResultPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn join_result_too_short() {
        assert!(matches!(
            JoinBootstrapResultPayload::decode(&[0u8; 34]),
            Err(ProtoError::BufferTooShort { need: 35, got: 34 }),
        ));
    }

    #[test]
    fn mobile_status_roundtrip_typical() {
        let p = MobileStatusPayload {
            background_tier: 1, // Active
            background_keepalive_multiplier: 60,
            background_keepalive_factor: 2,
            battery_level_pct: 75,
            low_battery_threshold_pct: 30,
            low_battery_multiplier: 4,
            battery_route_probe_factor: 1,
        };
        let buf = p.encode();
        assert_eq!(buf.len(), MobileStatusPayload::WIRE_SIZE);
        let d = MobileStatusPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn mobile_status_roundtrip_lowpower_low_battery() {
        let p = MobileStatusPayload {
            background_tier: 2, // LowPower
            background_keepalive_multiplier: 60,
            background_keepalive_factor: 60,
            battery_level_pct: 10,
            low_battery_threshold_pct: 30,
            low_battery_multiplier: 4,
            battery_route_probe_factor: 4, // throttle active
        };
        let buf = p.encode();
        let d = MobileStatusPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn mobile_status_roundtrip_ac_disabled() {
        let p = MobileStatusPayload {
            background_tier: 0,                 // Foreground
            background_keepalive_multiplier: 1, // feature off
            background_keepalive_factor: 1,
            battery_level_pct: MOBILE_BATTERY_AC_OR_UNKNOWN,
            low_battery_threshold_pct: MOBILE_LOW_BATTERY_THRESHOLD_DISABLED,
            low_battery_multiplier: 1,
            battery_route_probe_factor: 1,
        };
        let buf = p.encode();
        let d = MobileStatusPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn mobile_status_too_short() {
        assert!(matches!(
            MobileStatusPayload::decode(&[0u8; 18]),
            Err(ProtoError::BufferTooShort { need: 19, got: 18 }),
        ));
    }

    #[test]
    fn join_result_oversized_detail_rejected() {
        let mut buf = Vec::new();
        buf.push(0);
        buf.extend_from_slice(&[0u8; 32]);
        let oversized = (MAX_JOIN_DETAIL_LEN + 1) as u16;
        buf.extend_from_slice(&oversized.to_be_bytes());
        assert!(matches!(
            JoinBootstrapResultPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "join_result.detail_len",
                ..
            }),
        ));
    }

    // ── EventPayload ──────────────────────────

    #[test]
    fn event_payload_roundtrip_typical() {
        let p = EventPayload {
            kind: event_kind::SESSIONS_CHANGED,
            payload: 7u16.to_be_bytes().to_vec(),
        };
        let buf = p.encode();
        assert_eq!(buf.len(), EventPayload::FIXED_SIZE + 2);
        let d = EventPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn event_payload_roundtrip_empty_payload() {
        let p = EventPayload {
            kind: event_kind::IDENTITY_ROTATED,
            payload: Vec::new(),
        };
        let buf = p.encode();
        assert_eq!(buf.len(), EventPayload::FIXED_SIZE);
        let d = EventPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn event_payload_roundtrip_max_payload() {
        let p = EventPayload {
            kind: event_kind::MOBILE_TIER_CHANGED,
            payload: vec![0xABu8; MAX_EVENT_PAYLOAD_LEN],
        };
        let buf = p.encode();
        assert_eq!(buf.len(), EventPayload::FIXED_SIZE + MAX_EVENT_PAYLOAD_LEN);
        let d = EventPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn event_payload_mailbox_drained_roundtrip() {
        // MAILBOX_DRAINED carries a 4-byte BE drained-count payload —
        // pin both the kind constant and the wire layout so iOS / Android
        // BGProcessingTask handlers stay in sync with the Rust publisher.
        let p = EventPayload {
            kind: event_kind::MAILBOX_DRAINED,
            payload: 42u32.to_be_bytes().to_vec(),
        };
        let buf = p.encode();
        assert_eq!(buf.len(), EventPayload::FIXED_SIZE + 4);
        let d = EventPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
        // Constant value lockdown — wire byte stable across versions.
        assert_eq!(event_kind::MAILBOX_DRAINED, 3);
    }

    #[test]
    fn event_payload_unknown_kind_decodes() {
        // Forward-compat: a kind byte the SDK doesn't recognise must still
        // round-trip cleanly so older SDKs don't crash on newer events.
        let p = EventPayload {
            kind: 99,
            payload: b"future-kind".to_vec(),
        };
        let d = EventPayload::decode(&p.encode()).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn event_payload_too_short_for_header() {
        assert!(matches!(
            EventPayload::decode(&[0u8; 2]),
            Err(ProtoError::BufferTooShort { need: 3, got: 2 }),
        ));
    }

    #[test]
    fn event_payload_truncated_payload_rejected() {
        // Header claims payload_len=10 but only 5 payload bytes follow.
        let mut buf = Vec::new();
        buf.push(event_kind::SESSIONS_CHANGED);
        buf.extend_from_slice(&10u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 5]);
        assert!(matches!(
            EventPayload::decode(&buf),
            Err(ProtoError::BufferTooShort { need: 13, got: 8 }),
        ));
    }

    #[test]
    fn event_payload_oversized_rejected() {
        let mut buf = Vec::new();
        buf.push(event_kind::SESSIONS_CHANGED);
        let oversized = (MAX_EVENT_PAYLOAD_LEN + 1) as u16;
        buf.extend_from_slice(&oversized.to_be_bytes());
        assert!(matches!(
            EventPayload::decode(&buf),
            Err(ProtoError::ValueTooLarge {
                field: "event.payload_len",
                ..
            }),
        ));
    }

    /// wire-format invariant. Any change to a Payload's
    /// `WIRE_SIZE` (or `IPC_PROTOCOL_VERSION`) MUST come with a snapshot
    /// update + a coordinated bump of `IPC_PROTOCOL_VERSION` AND
    /// `CLIENT_MIN_VERSION` / `CLIENT_MAX_VERSION`. Otherwise this test
    /// fails — forcing the change author to acknowledge the wire-break
    /// contract instead of silently shipping a binary that's
    /// version-1-on-paper but byte-incompatible with previous v1 builds.
    ///
    /// Why this matters: discovered that ~10 commits to
    /// `veil-ipc/server.rs` between May 3 and May 5 had subtly
    /// changed wire semantics without bumping `IPC_PROTOCOL_VERSION`
    /// causing a May-3 chat_node binary to hang silently on Hello
    /// handshake against a May-5 daemon. Version check `1 == 1`
    /// passed; bytes diverged. This snapshot now catches that.
    ///
    /// To intentionally bump: update both the snapshot and the version
    /// constants, then update CLIENT_MIN/MAX_VERSION acceptance window.
    #[test]
    fn ipc_wire_format_snapshot() {
        // Snapshot of every public IPC payload's WIRE_SIZE + the
        // protocol version constants. Any field added/removed/resized
        // changes one of these numbers; the version bump must follow.
        let observed: Vec<(&'static str, usize)> = vec![
            ("IPC_PROTOCOL_VERSION", IPC_PROTOCOL_VERSION as usize),
            ("CLIENT_MIN_VERSION", CLIENT_MIN_VERSION as usize),
            ("CLIENT_MAX_VERSION", CLIENT_MAX_VERSION as usize),
            (
                "AppIpcHelloPayload::WIRE_SIZE",
                AppIpcHelloPayload::WIRE_SIZE,
            ),
            (
                "AppIpcHelloOkPayload::WIRE_SIZE",
                AppIpcHelloOkPayload::WIRE_SIZE,
            ),
            ("AppBindOkPayload::WIRE_SIZE", AppBindOkPayload::WIRE_SIZE),
            ("AppUnbindPayload::WIRE_SIZE", AppUnbindPayload::WIRE_SIZE),
            ("StreamOpenPayload::WIRE_SIZE", StreamOpenPayload::WIRE_SIZE),
            (
                "StreamOpenOkPayload::WIRE_SIZE",
                StreamOpenOkPayload::WIRE_SIZE,
            ),
            (
                "StreamOpenErrPayload::WIRE_SIZE",
                StreamOpenErrPayload::WIRE_SIZE,
            ),
            (
                "StreamClosePayload::WIRE_SIZE",
                StreamClosePayload::WIRE_SIZE,
            ),
            (
                "StreamWindowPayload::WIRE_SIZE",
                StreamWindowPayload::WIRE_SIZE,
            ),
        ];
        // Pinned snapshot — bump in lockstep with version constants.
        let expected: Vec<(&'static str, usize)> = vec![
            ("IPC_PROTOCOL_VERSION", 1),
            ("CLIENT_MIN_VERSION", 1),
            ("CLIENT_MAX_VERSION", 1),
            ("AppIpcHelloPayload::WIRE_SIZE", 6),
            ("AppIpcHelloOkPayload::WIRE_SIZE", 18),
            ("AppBindOkPayload::WIRE_SIZE", 36),
            ("AppUnbindPayload::WIRE_SIZE", 36),
            ("StreamOpenPayload::WIRE_SIZE", 72),
            ("StreamOpenOkPayload::WIRE_SIZE", 8),
            ("StreamOpenErrPayload::WIRE_SIZE", 2),
            ("StreamClosePayload::WIRE_SIZE", 4),
            ("StreamWindowPayload::WIRE_SIZE", 8),
        ];
        assert_eq!(
            observed, expected,
            "IPC wire-format changed but snapshot not updated.\n\
             If this is intentional:\n\
             1. Bump IPC_PROTOCOL_VERSION (and CLIENT_MIN/MAX_VERSION accordingly).\n\
             2. Update this snapshot to match the observed values.\n\
             3. Document the new wire format in the bumped version's spec.",
        );
    }

    // ── SetWakeHmacEnvelopePayload (Epic 489.10 slice 4.3.4) ─────────

    #[test]
    fn set_wake_hmac_envelope_payload_roundtrip_with_envelope() {
        let p = SetWakeHmacEnvelopePayload {
            rendezvous_node_id: [0xAAu8; 32],
            auth_cookie: [0xBBu8; 16],
            envelope: vec![0xCC; 92],
        };
        let buf = p.encode();
        assert_eq!(buf.len(), SetWakeHmacEnvelopePayload::MIN_WIRE_SIZE + 92);
        let d = SetWakeHmacEnvelopePayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn set_wake_hmac_envelope_payload_roundtrip_empty_envelope() {
        // Empty envelope = clear-registration semantics.
        let p = SetWakeHmacEnvelopePayload {
            rendezvous_node_id: [0u8; 32],
            auth_cookie: [0u8; 16],
            envelope: Vec::new(),
        };
        let buf = p.encode();
        assert_eq!(buf.len(), SetWakeHmacEnvelopePayload::MIN_WIRE_SIZE);
        let d = SetWakeHmacEnvelopePayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn set_wake_hmac_envelope_payload_rejects_oversized_envelope_at_decode() {
        // Encode a blob with envelope_len > MAX_WAKE_HMAC_ENVELOPE_BYTES,
        // confirm decoder rejects.  Catches malicious / corrupted wire
        // bytes on the daemon side.
        let mut buf = vec![0u8; 32 + 16];
        let bad_len = (MAX_WAKE_HMAC_ENVELOPE_BYTES + 1) as u16;
        buf.extend_from_slice(&bad_len.to_be_bytes());
        buf.extend(std::iter::repeat_n(0u8, MAX_WAKE_HMAC_ENVELOPE_BYTES + 1));
        let err = SetWakeHmacEnvelopePayload::decode(&buf).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)));
    }

    #[test]
    fn set_wake_hmac_envelope_status_wire_roundtrip() {
        for s in [
            SetWakeHmacEnvelopeStatus::Ok,
            SetWakeHmacEnvelopeStatus::NoMatchingRendezvous,
            SetWakeHmacEnvelopeStatus::EnvelopeTooLarge,
        ] {
            let byte = s as u8;
            assert_eq!(SetWakeHmacEnvelopeStatus::from_wire(byte).unwrap(), s);
        }
        assert!(SetWakeHmacEnvelopeStatus::from_wire(99).is_err());
    }
}
