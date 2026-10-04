#!/usr/bin/env python3
"""Test kernel WireGuard in isolated namespaces. Requires root, nftables and a WireGuard-capable kernel."""

import os
from pathlib import Path
import subprocess
import sys


def main():
    inside = len(sys.argv) == 3 and sys.argv[1] == "--inside"
    if not inside and len(sys.argv) != 2:
        raise SystemExit("Usage: wireguard-network.py /path/to/test-wireguard-admission")
    binary = str(Path(sys.argv[-1]).resolve())
    if os.geteuid() != 0:
        print("SKIP: kernel WireGuard integration requires root and network namespace support")
        return 77
    if not inside:
        # All veth creation happens in a new outer network namespace. /run mounts are private too.
        return subprocess.run([
            "unshare", "--net", "--mount", "--propagation", "private", sys.executable,
            str(Path(__file__).resolve()), "--inside", binary,
        ], timeout=45).returncode

    def run(*args):
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20)

    run("mount", "-t", "tmpfs", "tmpfs", "/run")
    Path("/run/netns").mkdir()
    namespaces = ["cocoon-wg-test-a", "cocoon-wg-test-b"]
    created = []
    try:
        for name in namespaces:
            run("/usr/sbin/ip", "netns", "add", name)
            created.append(name)
        run("/usr/sbin/ip", "link", "add", "veth-a", "type", "veth", "peer", "name", "veth-b")
        for rank, name in enumerate(namespaces):
            interface = f"veth-{'ab'[rank]}"
            run("/usr/sbin/ip", "link", "set", interface, "netns", name)
            run("/usr/sbin/ip", "-n", name, "link", "set", "lo", "up")
            run("/usr/sbin/ip", "-n", name, "address", "add", f"192.0.2.{rank + 1}/24", "dev", interface)
            run("/usr/sbin/ip", "-n", name, "link", "set", interface, "up")
        return subprocess.run([
            binary, "--network-integration", *(f"/run/netns/{name}" for name in namespaces)
        ], timeout=30).returncode
    finally:
        for name in reversed(created):
            subprocess.run(["/usr/sbin/ip", "netns", "delete", name], capture_output=True, timeout=10)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"WireGuard namespace integration failed: {error}", file=sys.stderr)
        if getattr(error, "stderr", None):
            print(error.stderr, file=sys.stderr)
        raise SystemExit(1)
