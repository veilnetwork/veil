#!/usr/bin/env python3
"""
chat_client.py — veil chat sender (the "client" side).

Connects to a local veil node, binds to the "chat" endpoint, sends one
message to the destination node, then exits.

Usage:
    python3 examples/chat_client.py <dst_node_id_hex> <message> [socket_path]

    dst_node_id_hex  — 64-char hex node_id of the destination node
                       (get it from `veil-cli node show` on the other machine)
    message          — text to send (wrap in quotes if it contains spaces)
    socket_path      — path to this node's IPC Unix socket
                       (default: ~/.veil/app.sock)

Example (two nodes, A sends to B):
    # On node B, find its node_id:
    veil-cli node show

    # On node A, send a message:
    python3 examples/chat_client.py \\
        aabbccdd....(64 hex chars).... \\
        "hello from A"

Requirements:
  - Both nodes must be running (`veil-cli node run`).
  - Node A must have node B configured as a peer (direct OVL1 session).
    For multi-hop routing, relay support is not yet implemented — see backlog.
"""

import sys
from ovl_proto import OvlClient, DeliveryError, DEFAULT_SOCKET

NAMESPACE   = "examples"
ENDPOINT_ID = 1


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    dst_hex     = sys.argv[1]
    message     = sys.argv[2]
    socket_path = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_SOCKET

    if len(dst_hex) != 64:
        print(f"error: dst_node_id must be 64 hex chars, got {len(dst_hex)}", file=sys.stderr)
        sys.exit(1)

    dst_node_id = bytes.fromhex(dst_hex)
    payload     = message.encode()

    print(f"connecting to {socket_path} …")
    with OvlClient(socket_path) as client:
        # Ephemeral bind: our app_id is unique per connection, so multiple
        # chat_client instances can run simultaneously on the same node.
        # The remote chat server must use bind_named() so its address is stable
        # and can be derived with compute_app_id() below.
        app_id = client.bind(NAMESPACE, "chat", ENDPOINT_ID)
        print(f"bound  app_id={app_id.hex()} (ephemeral)")

        print(f"sending {len(payload)} bytes → {dst_hex[:16]}…")
        client.send(dst_node_id, payload, require_ack=True)
        print("sent  ✓")

        try:
            _, _src_app_id, _src_ep, reply = client.recv(timeout=30.0)
            print(f"server: {reply.decode(errors='replace')}")
        except DeliveryError as exc:
            print(f"[warn] delivery failed: {exc}", file=sys.stderr)
            sys.exit(2)


if __name__ == "__main__":
    main()
