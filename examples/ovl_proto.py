"""
OVL1 IPC protocol helpers.

Wire format
-----------
Every frame = 24-byte header + body_len bytes body.

Header layout (all big-endian):
  [0..4]   magic      b"OVL1"
  [4]      version    1
  [5]      family     FrameFamily discriminant
  [6..8]   msg_type   u16
  [8..10]  flags      u16
  [10..12] header_len u16  (always 24 for us)
  [12..16] body_len   u32
  [16..20] stream_id  u32
  [20..24] request_id u32
"""

import socket
import struct
import os
from typing import Tuple, Optional

try:
    import blake3 as _blake3_pkg
    def _blake3_digest(*parts: bytes) -> bytes:
        h = _blake3_pkg.blake3()
        for p in parts:
            h.update(p)
        return h.digest()

    def _blake3_derive_key(context: str, ikm: bytes) -> bytes:
        """BLAKE3 key-derivation mode (RFC-style domain separator)."""
        h = _blake3_pkg.blake3(derive_key_context=context)
        h.update(ikm)
        return h.digest()
except ImportError:
    raise ImportError(
        "blake3 package required: pip install blake3"
    )


class DeliveryError(RuntimeError):
    """Raised when the node reports permanent delivery failure (APP_SEND_FAILED)."""
    def __init__(self, msg: str, content_id: bytes = b""):
        super().__init__(msg)
        self.content_id = content_id


def compute_app_id(node_id: bytes, namespace: str, name: str) -> bytes:
    """Compute the stable (named) app_id.

    Formula (Epic 452 — length-prefixed + domain separator):

        app_id = BLAKE3-derive_key(
            context = "veil.app_id.v1",
            ikm     = node_id || ns_len(u32 BE) || namespace
                             || name_len(u32 BE) || name,
        )

    This matches `veilcore::node::app::address::app_id` exactly.  The
    length-prefixes are mandatory — without them ("foo","bar") and
    ("fo","obar") would collide into the same hash.
    """
    ns_bytes = namespace.encode()
    name_bytes = name.encode()
    ikm = (
        node_id
        + struct.pack(">I", len(ns_bytes)) + ns_bytes
        + struct.pack(">I", len(name_bytes)) + name_bytes
    )
    return _blake3_derive_key("veil.app_id.v1", ikm)


def compute_ephemeral_app_id(
    node_id: bytes,
    client_token: bytes,
    namespace: str,
    name: str,
) -> bytes:
    """Compute the ephemeral app_id (for `bind()`-style default).

    Formula: identical to `compute_app_id` but with a distinct
    derive_key context AND the per-connection `client_token` (16 bytes)
    mixed into the IKM immediately after `node_id`.

    Matches `veilcore::node::app::address::ephemeral_app_id`.
    """
    if len(client_token) != 16:
        raise ValueError("client_token must be 16 bytes")
    ns_bytes = namespace.encode()
    name_bytes = name.encode()
    ikm = (
        node_id
        + client_token
        + struct.pack(">I", len(ns_bytes)) + ns_bytes
        + struct.pack(">I", len(name_bytes)) + name_bytes
    )
    return _blake3_derive_key("veil.ephemeral_app_id.v1", ikm)

# ── Constants ─────────────────────────────────────────────────────────────────

MAGIC         = b"OVL1"
VERSION       = 1
HEADER_SIZE   = 24
HEADER_LEN    = 24          # no TLV extensions

# FrameFamily
FAMILY_LOCAL_APP = 6

# LocalAppMsg
MSG_APP_HELLO      = 0
MSG_APP_HELLO_OK   = 1
MSG_APP_HELLO_ERR  = 2
MSG_APP_BIND       = 3
MSG_APP_BIND_OK    = 4
MSG_APP_BIND_ERR   = 5
MSG_APP_UNBIND     = 6
MSG_APP_DELIVER    = 7
MSG_APP_IPC_SEND   = 8
MSG_APP_SEND_OK    = 9
MSG_APP_SEND_FAILED = 17
MSG_APP_RT_SEND     = 18
MSG_DELIVERY_STAGE  = 19
MSG_ANYCAST_RESOLVE   = 20
MSG_ANYCAST_RESULT    = 21
MSG_ANYCAST_ADVERTISE = 22  # Epic 454.14
MSG_ANYCAST_WITHDRAW  = 23  # Epic 454.14
MSG_TRANSPORT_HINT_QUERY  = 24  # Epic 455.1
MSG_TRANSPORT_HINT_RESULT = 25  # Epic 455.1

# IPC_SEND flags
IPC_SEND_FLAG_REQUIRE_ACK = 0x0000_0001
IPC_SEND_FLAG_ANONYMOUS   = 0x0000_0002

# Error codes (must match ipc_send_err in veilcore/src/proto/ipc.rs)
IPC_SEND_ERR_RATE_LIMITED = 1
IPC_SEND_ERR_NO_ROUTE     = 2
IPC_SEND_ERR_NO_E2E_KEY   = 3
IPC_SEND_ERR_SPOOFED_SRC  = 4

IPC_PROTOCOL_VERSION = 1

# APP_BIND flags
IPCBIND_EPHEMERAL = 0x0001   # mix client_token into app_id derivation (unique per connection)

DEFAULT_SOCKET = os.path.expanduser("~/.veil/app.sock")


# ── Low-level frame I/O ───────────────────────────────────────────────────────

def encode_header(family: int, msg_type: int, body_len: int) -> bytes:
    return struct.pack(
        ">4sBBHHHIII",
        MAGIC,
        VERSION,
        family,
        msg_type,
        0,              # flags
        HEADER_LEN,
        body_len,
        0,              # stream_id
        0,              # request_id
    )


def send_frame(sock: socket.socket, family: int, msg_type: int, body: bytes = b"") -> None:
    hdr = encode_header(family, msg_type, len(body))
    sock.sendall(hdr + body)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed unexpectedly")
        buf += chunk
    return buf


def recv_frame(sock: socket.socket) -> Tuple[int, int, bytes]:
    """Read one frame. Returns (family, msg_type, body)."""
    hdr = recv_exact(sock, HEADER_SIZE)
    magic = hdr[0:4]
    if magic != MAGIC:
        raise ValueError(f"bad magic: {magic!r}")
    family    = hdr[5]
    msg_type  = struct.unpack_from(">H", hdr, 6)[0]
    body_len  = struct.unpack_from(">I", hdr, 12)[0]
    body = recv_exact(sock, body_len) if body_len else b""
    return family, msg_type, body


# ── High-level IPC client ─────────────────────────────────────────────────────

def _connect_ipc_any(anchor: str):
    """
    Epic 451.6b: dispatch on whichever IPC backend the node is bound to.

    If `anchor`'s parent dir contains both `ipc.port` and `ipc.token`, treat
    as TCP-loopback: read the port + 32-byte token, connect to
    `127.0.0.1:port`, send the token as the first frame, return the socket.
    Otherwise treat `anchor` as the Unix-socket path directly (legacy).

    Mirrors `veilclient::connect_ipc_any` in the Rust client so app code
    is unaffected by Unix↔TCP backend switches.
    """
    import os
    parent = os.path.dirname(anchor) or "."
    port_path = os.path.join(parent, "ipc.port")
    token_path = os.path.join(parent, "ipc.token")
    if os.path.exists(port_path) and os.path.exists(token_path):
        with open(port_path, "rt") as f:
            port = int(f.read().strip())
        with open(token_path, "rt") as f:
            token_hex = f.read().strip()
        if len(token_hex) != 64:
            raise RuntimeError(f"ipc.token has wrong length: {len(token_hex)} != 64")
        token = bytes.fromhex(token_hex)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        sock.sendall(token)
        return sock
    # Fallback: Unix domain socket (Linux/macOS only — Windows has no AF_UNIX).
    if not hasattr(socket, "AF_UNIX"):
        raise RuntimeError(
            f"IPC backend at {anchor!r} appears to be a Unix socket but this "
            "platform has no AF_UNIX.  Configure the node with "
            "`[ipc] socket_uri = \"tcp://127.0.0.1:0\"` to use the TCP backend."
        )
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(anchor)
    return sock


class OvlClient:
    """
    Veil IPC client.  Connects to the node's IPC backend (Unix socket OR
    TCP-loopback with token, picked automatically — see `_connect_ipc_any`),
    performs APP_HELLO, and exposes bind / send / recv.
    """

    def __init__(self, socket_path: str = DEFAULT_SOCKET):
        self._sock = _connect_ipc_any(socket_path)
        # Buffer for APP_DELIVER frames that arrive while send() is waiting for APP_SEND_OK.
        self._deliver_buffer: list = []
        self._do_hello()

    def close(self) -> None:
        self._sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # ── handshake ──────────────────────────────────────────────────────────

    def _do_hello(self) -> None:
        # APP_HELLO body: version(u16) + flags(u32)
        body = struct.pack(">HI", IPC_PROTOCOL_VERSION, 0)
        send_frame(self._sock, FAMILY_LOCAL_APP, MSG_APP_HELLO, body)

        try:
            family, msg_type, body = recv_frame(self._sock)
        except (ConnectionError, ValueError) as exc:
            raise ConnectionError(
                f"IPC handshake failed ({exc}). "
                "Make sure you are connecting to the IPC socket (app.sock), "
                "not the admin socket (config.sock)."
            ) from exc
        if msg_type == MSG_APP_HELLO_ERR:
            code = struct.unpack_from(">H", body)[0] if len(body) >= 2 else 0
            detail = body[4:].decode(errors="replace") if len(body) > 4 else ""
            raise RuntimeError(f"APP_HELLO_ERR code={code} detail={detail!r}")
        if msg_type != MSG_APP_HELLO_OK:
            raise RuntimeError(f"unexpected msg_type={msg_type} after APP_HELLO")
        # body: version(u16) + client_token(16 bytes)
        if len(body) >= 18:
            self._client_token: bytes = body[2:18]
        else:
            self._client_token = b"\x00" * 16

    # ── bind ───────────────────────────────────────────────────────────────

    def bind(self, namespace: str, name: str, endpoint_id: int = 1) -> bytes:
        """
        Register an endpoint in **ephemeral** mode (default for most apps).

        The node mixes the per-connection client_token into app_id derivation:
          app_id = BLAKE3(node_id || client_token || namespace || name)
        so multiple processes using the same (namespace, name, endpoint_id)
        each receive a distinct address.

        Returns the 32-byte app_id assigned by the node.
        """
        return self._bind_with_flags(namespace, name, endpoint_id, IPCBIND_EPHEMERAL)

    def bind_named(self, namespace: str, name: str, endpoint_id: int = 1) -> bytes:
        """
        Register an endpoint in **named** mode.

        app_id = BLAKE3(node_id || namespace || name) — deterministic and stable
        across reconnects.  Only one client on a node may hold a given
        (namespace, name, endpoint_id) at a time.

        Use this for well-known services that need a stable, node-scoped address.
        For apps that may run as multiple instances, prefer bind().

        Returns the 32-byte app_id assigned by the node.
        """
        return self._bind_with_flags(namespace, name, endpoint_id, 0)

    def _bind_with_flags(self, namespace: str, name: str, endpoint_id: int, flags: int) -> bytes:
        ns_bytes   = namespace.encode()
        name_bytes = name.encode()
        body = struct.pack(">IHH", endpoint_id, flags, len(ns_bytes))
        body += ns_bytes
        body += struct.pack(">H", len(name_bytes))
        body += name_bytes

        send_frame(self._sock, FAMILY_LOCAL_APP, MSG_APP_BIND, body)

        _, msg_type, resp = recv_frame(self._sock)
        if msg_type == MSG_APP_BIND_ERR:
            code = struct.unpack_from(">H", resp)[0] if len(resp) >= 2 else 0
            raise RuntimeError(f"APP_BIND_ERR code={code}")
        if msg_type != MSG_APP_BIND_OK:
            raise RuntimeError(f"unexpected msg_type={msg_type} after APP_BIND")
        # body: app_id(32) + endpoint_id(4)
        app_id = resp[0:32]
        self._app_id       = app_id
        self._endpoint_id  = endpoint_id
        self._namespace    = namespace
        self._name         = name
        return app_id

    # ── send ───────────────────────────────────────────────────────────────

    def send(
        self,
        dst_node_id: bytes,
        data: bytes,
        app_id: Optional[bytes] = None,
        endpoint_id: Optional[int] = None,
        require_ack: bool = False,
    ) -> None:
        """
        Send a datagram to dst_node_id.
        app_id / endpoint_id default to the values from the last bind().
        If require_ack is True, the node will retransmit on delivery failure
        and notify the app via APP_SEND_FAILED if all attempts are exhausted.
        """
        if len(dst_node_id) != 32:
            raise ValueError("dst_node_id must be 32 bytes")
        # Routing key on the destination node = BLAKE3(dst_node_id || ns || name).
        # Never use the sender's own app_id here — it belongs to a different node.
        if app_id is not None:
            aid = app_id
        else:
            aid = compute_app_id(dst_node_id, self._namespace, self._name)
        eid = endpoint_id if endpoint_id is not None else self._endpoint_id

        flags = 0
        if require_ack:
            flags |= IPC_SEND_FLAG_REQUIRE_ACK

        # Wire: dst_node_id(32) + src_app_id(32) + dst_app_id(32) + endpoint_id(4) + flags(4) + data_len(4) + data
        body = dst_node_id + self._app_id + aid
        body += struct.pack(">III", eid, flags, len(data))
        body += data

        send_frame(self._sock, FAMILY_LOCAL_APP, MSG_APP_IPC_SEND, body)

        # Wait for APP_SEND_OK/ERR, buffering any APP_DELIVER that arrive in the meantime.
        while True:
            _, msg_type, resp = recv_frame(self._sock)
            if msg_type == MSG_APP_SEND_OK:
                return
            if msg_type == MSG_APP_DELIVER:
                self._deliver_buffer.append(resp)
                continue
            # Send errors arrive as APP_SEND_FAILED (msg_type=17) or legacy
            # APP_HELLO_ERR (msg_type=2).
            if msg_type == MSG_APP_SEND_FAILED or msg_type == MSG_APP_HELLO_ERR:
                code = struct.unpack_from(">H", resp)[0] if len(resp) >= 2 else 0
                if code == IPC_SEND_ERR_RATE_LIMITED:
                    raise RuntimeError("send rate-limited by node")
                if code == IPC_SEND_ERR_NO_ROUTE:
                    raise RuntimeError(
                        f"no active OVL1 session to {dst_node_id.hex()[:8]}… "
                        "(node not connected or not a direct peer)"
                    )
                if code == IPC_SEND_ERR_NO_E2E_KEY:
                    raise RuntimeError(
                        f"E2E key for {dst_node_id.hex()[:8]}… not yet cached — "
                        "retry after AnnounceAttachment propagates"
                    )
                if code == IPC_SEND_ERR_SPOOFED_SRC:
                    raise RuntimeError("send rejected: src_app_id not registered on this connection")
                raise RuntimeError(f"send error code={code}")
            # Any other frame type (e.g. stream notifications) — skip and keep waiting.
            continue

    # ── anycast (Epic 239 + 454.14) ────────────────────────────────────────

    def anycast_advertise(self, service_tag: bytes, score: int = 0, ttl_secs: int = 3600) -> None:
        """Announce this node as a provider of `service_tag` (4 bytes).

        `score` is a routing-quality hint (lower = better; 0 = no info).
        Re-publish before `ttl_secs` elapses to keep the entry fresh.
        """
        if len(service_tag) != 4:
            raise ValueError("service_tag must be exactly 4 bytes")
        body = service_tag + struct.pack(">HI", score, ttl_secs)
        send_frame(self._sock, FAMILY_LOCAL_APP, MSG_ANYCAST_ADVERTISE, body)

    def anycast_withdraw(self, service_tag: bytes) -> None:
        """Remove this node's advertisement for `service_tag`."""
        if len(service_tag) != 4:
            raise ValueError("service_tag must be exactly 4 bytes")
        send_frame(self._sock, FAMILY_LOCAL_APP, MSG_ANYCAST_WITHDRAW, service_tag)

    def anycast_resolve(self, service_tag: bytes, max_results: int = 8) -> list:
        """Resolve `service_tag` to a list of candidate `node_id` (bytes[32]).

        Returns the list sorted by score (best first), capped at
        `MAX_ANYCAST_CANDIDATES` (32).  Empty list = no providers known.
        """
        if len(service_tag) != 4:
            raise ValueError("service_tag must be exactly 4 bytes")
        max_results = max(1, min(32, int(max_results)))
        body = service_tag + bytes([max_results])
        send_frame(self._sock, FAMILY_LOCAL_APP, MSG_ANYCAST_RESOLVE, body)
        family, msg_type, body = recv_frame(self._sock)
        if family != FAMILY_LOCAL_APP or msg_type != MSG_ANYCAST_RESULT:
            raise RuntimeError(f"unexpected anycast response: family={family} msg_type={msg_type}")
        if len(body) < 5:
            raise RuntimeError(f"anycast result too short: {len(body)} bytes")
        count = body[4]
        if len(body) < 5 + count * 32:
            raise RuntimeError("anycast result truncated")
        return [body[5 + i*32 : 5 + (i+1)*32] for i in range(count)]

    # ── transport hints (Epic 455.1) ───────────────────────────────────────

    def transport_hints(self) -> list:
        """Query the local node for ranked transport-success observations.

        Returns a list of dicts: ``[{"scheme": "tls", "success_pct": 95,
        "sample_count": 200}, ...]``, sorted best-first by success rate.

        Use case: choose which transport to bias toward when reconnecting,
        or report observed transport viability up to a control plane.
        """
        send_frame(self._sock, FAMILY_LOCAL_APP, MSG_TRANSPORT_HINT_QUERY, b"")
        family, msg_type, body = recv_frame(self._sock)
        if family != FAMILY_LOCAL_APP or msg_type != MSG_TRANSPORT_HINT_RESULT:
            raise RuntimeError(
                f"unexpected hint response: family={family} msg_type={msg_type}"
            )
        if len(body) < 1:
            raise RuntimeError(f"hint result too short: {len(body)} bytes")
        count = body[0]
        out = []
        pos = 1
        for _ in range(count):
            if pos + 1 > len(body):
                raise RuntimeError("hint result truncated at scheme_len")
            scheme_len = body[pos]
            pos += 1
            if pos + scheme_len + 3 > len(body):
                raise RuntimeError("hint result truncated at scheme/score block")
            scheme = body[pos:pos + scheme_len].decode("utf-8")
            pos += scheme_len
            success_pct = body[pos]
            pos += 1
            sample_count = struct.unpack(">H", body[pos:pos + 2])[0]
            pos += 2
            out.append({
                "scheme": scheme,
                "success_pct": success_pct,
                "sample_count": sample_count,
            })
        return out

    # ── receive ────────────────────────────────────────────────────────────

    def recv(self, timeout: Optional[float] = None) -> Tuple[bytes, bytes, int, bytes]:
        """
        Block until an APP_DELIVER frame arrives.
        Returns (src_node_id: bytes[32], src_app_id: bytes[32], src_endpoint_id: int, data: bytes).
        Raises TimeoutError on timeout.
        """
        def _parse_deliver(body: bytes):
            # Wire: src_node_id(32) + src_app_id(32) + dst_app_id(32) + endpoint_id(4) + data_len(4) + data
            if len(body) < 104:
                return None
            src_node_id     = body[0:32]
            src_app_id      = body[32:64]
            # dst_app_id    = body[64:96]  (this endpoint's app_id — not needed here)
            src_endpoint_id = struct.unpack_from(">I", body, 96)[0]
            data_len        = struct.unpack_from(">I", body, 100)[0]
            data            = body[104: 104 + data_len]
            return src_node_id, src_app_id, src_endpoint_id, data

        # Check buffer first (frames that arrived while send() was waiting for ACK).
        while self._deliver_buffer:
            parsed = _parse_deliver(self._deliver_buffer.pop(0))
            if parsed:
                return parsed

        self._sock.settimeout(timeout)
        try:
            while True:
                family, msg_type, body = recv_frame(self._sock)
                if family != FAMILY_LOCAL_APP:
                    continue
                if msg_type == MSG_APP_DELIVER:
                    parsed = _parse_deliver(body)
                    if parsed:
                        return parsed
                elif msg_type == MSG_APP_SEND_FAILED:
                    # Delivery permanently failed (all retransmits exhausted).
                    content_id = body[:32] if len(body) >= 32 else b""
                    raise DeliveryError(
                        f"delivery failed for content_id={content_id.hex()[:16]}…",
                        content_id=content_id,
                    )
                # Skip other frame types (DELIVERY_STAGE, stream, etc.)
        except TimeoutError:
            raise
        finally:
            self._sock.settimeout(None)
