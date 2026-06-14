#!/usr/bin/env python3
"""
chat_server.py — veil chat receiver (the "server" side).

Connects to a local veil node, binds to the "chat" endpoint,
and prints every message it receives together with the sender's node_id.

Usage:
    python3 examples/chat_server.py [socket_path]

    socket_path  — path to the node's IPC Unix socket
                   (default: ~/.veil/app.sock)

Example (two terminals, two nodes):
    # Terminal 1 — node B
    python3 examples/chat_server.py ~/.veil/app.sock

    # Terminal 2 — node A
    python3 examples/chat_client.py <node_B_id_hex> "hello from A"
"""

import sys
import signal
from datetime import datetime
from ovl_proto import OvlClient, DeliveryError, DEFAULT_SOCKET

NAMESPACE   = "examples"
ENDPOINT_ID = 1


def main() -> None:
    socket_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SOCKET

    print(f"connecting to {socket_path} …")
    with OvlClient(socket_path) as client:
        # Named bind: stable address so clients can compute it via compute_app_id().
        app_id = client.bind_named(NAMESPACE, "chat", ENDPOINT_ID)
        print(f"bound  app_id={app_id.hex()}")
        print(f"       endpoint_id={ENDPOINT_ID}")
        print("waiting for messages  (Ctrl-C to quit)\n")

        def _on_sigint(*_):
            print("\nbye.")
            sys.exit(0)

        signal.signal(signal.SIGINT, _on_sigint)

        while True:
            try:
                src_node_id, src_app_id, src_endpoint_id, data = client.recv()
            except DeliveryError as exc:
                # APP_SEND_FAILED for a previous echo reply — not fatal.
                print(f"[warn] delivery failed: {exc}")
                continue

            text = data.decode(errors='replace')
            print(f"[{src_node_id.hex()[:16]}…]  {text}")

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            reply = f"[{now}] echo: {text}".encode()
            # Reply to sender's exact app_id (may be ephemeral) and endpoint.
            # require_ack=False for echo replies: the client uses ephemeral
            # endpoints that disconnect after recv(), so ACKs would always
            # fail and flood the server with APP_SEND_FAILED warnings.
            try:
                client.send(src_node_id, reply, app_id=src_app_id, endpoint_id=src_endpoint_id)
            except RuntimeError as exc:
                print(f"[warn] reply failed: {exc}")


if __name__ == "__main__":
    main()
