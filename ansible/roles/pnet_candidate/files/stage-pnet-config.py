"""Prepare a local candidate in a private administrator-owned directory."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib


NETWORK_HEADER = re.compile(r"(?m)^[ \t]*\[[ \t]*network[ \t]*\][ \t]*(?:#[^\n]*)?\r?$")
NEXT_TABLE = re.compile(r"(?m)^[ \t]*\[|^# END ANSIBLE MANAGED — P-Net config$")
SIGNED_CONFIG = re.compile(r"(?m)^[ \t]*# VEIL_CONFIG_SIGNATURE_V1:")
PRIVATE_MODES = {"private", "private_configured"}
NETWORK_KEYS = {
    "mode",
    "network_id",
    "owner_pubkey",
    "owner_algo",
    "membership_cert",
    "admin_node_ids",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse_config(text):
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ValueError("could not parse node TOML") from error


def read_regular_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"{path.name} must be a regular file")
        return stream.read()


def stage(source, stage_dir, cert_base, settings):
    if not cert_base.is_absolute():
        raise ValueError("certificate destination must be an absolute path")
    original = read_regular_file(source)
    text = original.decode("utf-8")
    config = parse_config(text)
    has_network = "network" in config
    previous = config.pop("network", {})
    if not isinstance(previous, dict) or previous.keys() - NETWORK_KEYS:
        raise ValueError("network settings require a separately prepared config")

    certificate = (stage_dir / "candidate.cert").read_bytes()
    cert_digest = digest(certificate)
    cert_path = cert_base.with_name(f"{cert_base.stem}.{cert_digest}{cert_base.suffix}")

    network = dict(previous)
    previous_mode = previous.get("mode", "public")
    if previous_mode != "public" and previous_mode not in PRIVATE_MODES:
        raise ValueError("existing network mode requires a separately prepared config")
    network.update({
        "mode": settings["mode"] or ("private" if previous_mode == "public" else previous_mode),
        "network_id": settings["network_id"],
        "owner_pubkey": settings["owner_pubkey"],
        "owner_algo": settings["owner_algo"],
        "membership_cert": str(cert_path),
    })
    if network["mode"] not in PRIVATE_MODES:
        raise ValueError("deployment mode must be private or private_configured")
    if previous_mode in PRIVATE_MODES:
        if any(previous.get(key) != network[key] for key in ("network_id", "owner_pubkey", "owner_algo")):
            raise ValueError("existing private authority differs; use the owner rotation procedure")
        if previous_mode == "private_configured" and network["mode"] == "private":
            raise ValueError("configured-only discovery requires private_configured mode")
    else:
        network["admin_node_ids"] = settings["admin_node_ids"]

    if network != previous:
        if SIGNED_CONFIG.search(text):
            raise ValueError("signed node config requires an independently signed candidate")
        block = "[network]\n" + "".join(
            f"{key} = {json.dumps(value, ensure_ascii=False)}\n" for key, value in network.items()
        )
        expected = {**config, "network": network}
        if not has_network:
            text += "\n\n" + block
        else:
            for header in NETWORK_HEADER.finditer(text):
                end = NEXT_TABLE.search(text, header.end())
                tail = text[end.start():] if end else ""
                candidate = text[:header.start()] + block + "\n" + tail
                try:
                    if parse_config(candidate) == expected:
                        text = candidate
                        break
                except ValueError:
                    continue
            else:
                raise ValueError("could not replace [network] while preserving other fields")
        if parse_config(text) != expected:
            raise ValueError("network update would alter unrelated configuration")

    candidate = text.encode("utf-8")
    candidate_config = stage_dir / source.name
    candidate_config.write_bytes(candidate)
    sidecar = source.with_suffix(".runtime-state.toml")
    try:
        state = read_regular_file(sidecar)
    except FileNotFoundError:
        pass
    else:
        candidate_config.with_suffix(".runtime-state.toml").write_bytes(state)
    return {
        "source": digest(original),
        "candidate": digest(candidate),
        "certificate": cert_digest,
        "certificate_path": str(cert_path),
    }


if __name__ == "__main__":
    try:
        source, scratch, prefix, options = sys.argv[1:]
        print(json.dumps(stage(Path(source), Path(scratch), Path(prefix), json.loads(options))))
    except (OSError, ValueError) as error:
        sys.exit(f"P-Net preflight: {error}")
