"""Check explicitly selected paths through Linux TUN interfaces."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import time


INTERFACE_NAME = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_.-]{0,14}")


def parse_probes(raw):
    probes = json.loads(raw)
    if not isinstance(probes, list):
        raise ValueError("pnet_tunnel_probes must be a list")
    paths = []
    for entry in probes:
        if not isinstance(entry, dict) or entry.keys() != {"interface", "address"}:
            raise ValueError("each P-Net probe requires interface and address")
        interface = entry["interface"]
        if not isinstance(interface, str) or not INTERFACE_NAME.fullmatch(interface):
            raise ValueError("invalid Linux interface name in P-Net probe")
        address = entry["address"]
        if not isinstance(address, str) or "%" in address:
            raise ValueError("the P-Net probe address must be an IP literal without a zone")
        address = ipaddress.ip_address(address)
        if address.version == 6 and address.ipv4_mapped is not None:
            raise ValueError("use a plain IPv4 address for an IPv4 P-Net probe")
        if address.is_loopback or address.is_multicast or address.is_unspecified:
            raise ValueError("the P-Net probe requires a remote unicast address")
        paths.append((interface, address))
    return list(dict.fromkeys(paths))


def run(command, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return subprocess.run(
        command, capture_output=True, text=True, timeout=min(remaining, 2), check=False
    )


def ip_row(arguments, deadline):
    result = run(["ip", "-j", *arguments], deadline)
    if result.returncode != 0:
        return {}
    rows = json.loads(result.stdout)
    return rows[0] if len(rows) == 1 else {}


def try_probe(path, deadline):
    interface, address = path
    family = f"-{address.version}"
    try:
        link = ip_row(["-details", "link", "show", "dev", interface], deadline)
        if not link:
            return "interface unavailable"
        info = link.get("linkinfo", {})
        if info.get("info_kind") != "tun" or info.get("info_data", {}).get("type") != "tun":
            return "interface is not a TUN device"
        route = ip_row([family, "route", "get", str(address), "oif", interface], deadline)
        if route.get("type") == "local":
            return "destination belongs to this host"
        if route.get("dev") != interface or route.get("type", "unicast") != "unicast":
            return "no unicast route through the selected TUN"
        result = run(
            ["ping", family, "-n", "-c", "1", "-W", "1", "-I", interface, str(address)],
            deadline,
        )
        if result.returncode == 0:
            return None
        return result.stderr.strip() or "no ICMP echo reply"
    except (TimeoutError, subprocess.TimeoutExpired):
        return "probe timed out"


def verify(paths, wait_seconds):
    if not paths:
        return
    deadline = time.monotonic() + wait_seconds
    pending = dict.fromkeys(paths, "no probe completed")
    with ThreadPoolExecutor(max_workers=min(4, len(paths))) as pool:
        while pending and time.monotonic() < deadline:
            batch = list(pending)
            for path, error in zip(batch, pool.map(lambda path: try_probe(path, deadline), batch)):
                interface, address = path
                if error is None:
                    del pending[path]
                    print(f"{interface} → {address}: echo reply")
                else:
                    pending[path] = error
            if pending:
                time.sleep(max(0, min(0.5, deadline - time.monotonic())))
    if pending:
        failures = "\n".join(
            f"{interface} → {address}: {error}"
            for (interface, address), error in pending.items()
        )
        raise ValueError(f"tunnel verification failed after {wait_seconds}s\n{failures}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--wait-seconds", type=int, required=True)
    parser.add_argument("probes", help="JSON list of interface and address pairs")
    args = parser.parse_args()
    if args.wait_seconds <= 0:
        raise ValueError("pnet_tunnel_probe_timeout must be a positive number of seconds")
    paths = parse_probes(args.probes)
    if paths:
        for tool in ("ip", "ping"):
            if shutil.which(tool) is None:
                raise ValueError(f"{tool} is required for P-Net tunnel probes")
    if not args.validate:
        verify(paths, args.wait_seconds)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(f"P-Net tunnel check: {error}")
