#!/usr/bin/env python3
"""Exercise enrollment CLI and verify its signatures/keys independently with OpenSSL."""

import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: wireguard-cli.py /path/to/cocoon-wireguard")
    binary = str(Path(sys.argv[1]).resolve())
    repository = Path(__file__).resolve().parents[2]
    commands = 0

    def run(*args, input_bytes=None, code=0):
        nonlocal commands
        result = subprocess.run(args, input=input_bytes, capture_output=True, timeout=15)
        commands += 1
        assert result.returncode == code, (
            f"{Path(args[0]).name} exited {result.returncode}, expected {code}: "
            f"{result.stderr.decode(errors='replace')}"
        )
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="cocoon-wireguard-cli-") as temporary:
        directory = Path(temporary)
        signer = directory / "signer.pem"
        run("openssl", "genpkey", "-algorithm", "ED25519", "-out", str(signer))
        signer.chmod(0o600)
        public_der = run("openssl", "pkey", "-in", str(signer), "-pubout", "-outform", "DER")
        assert len(public_der) == 44 and public_der[:12].hex() == "302a300506032b6570032100"
        public_key = base64.b64encode(public_der[-32:]).decode()
        public_path = directory / "signer.pub.der"
        public_path.write_bytes(public_der)
        configurations, identities = [], []
        for node in ("a", "b"):
            template = repository / "scripts" / "wireguard" / f"worker-{node}.example.json"
            config = json.loads(template.read_text())
            config["membership_signer_public_key_b64"] = public_key
            config["workload_policy_sha256"] = "1" * 64
            config["attestation"]["allowed_image_hashes_hex"] = ["a" * 64]
            config_path = directory / f"worker-{node}.json"
            config_path.write_text(json.dumps(config))
            configurations.append(config_path)
            run(binary, "check-config", "--config", str(config_path))
            state = directory / f"identity-{node}"
            offer = directory / f"enrollment-{node}.json"
            assert not state.exists()
            run(binary, "enroll", "--config", str(config_path), "--state-dir", str(state), "--output", str(offer))
            identity = json.loads(offer.read_text())
            identities.append(identity)
            assert identity["attestation_status"] == "not_collected"
            assert len(base64.b64decode(identity["wireguard_public_key_b64"], validate=True)) == 32
            assert len(bytes.fromhex(identity["boot_id"])) == 32
            assert state.stat().st_mode & 0o777 == 0o700
            assert (state / "identity.bin").stat().st_mode & 0o777 == 0o600
            again = json.loads(run(binary, "enroll", "--config", str(config_path), "--state-dir", str(state)))
            assert again == identity
            run(binary, "enroll", "--config", str(config_path), "--state-dir", str(state), "--output", str(offer), code=1)
            # Read test-owned state only, and derive its public key with the independent OpenSSL CLI.
            raw_state = (state / "identity.bin").read_bytes()
            assert len(raw_state) == 140
            seed = raw_state[76:108]
            private_der = bytes.fromhex("302e020100300506032b656e04220420") + seed
            independent_pub = run("openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER", input_bytes=private_der)
            assert base64.b64encode(independent_pub[-32:]).decode() == identity["wireguard_public_key_b64"]
            assert base64.b64encode(seed).decode() not in offer.read_text()

        now = int(time.time())
        payload = {
            "format": "cocoon-wireguard-membership-v1",
            "cluster_id": identities[0]["cluster_id"],
            "workload_policy_sha256": "1" * 64,
            "generation": 1,
            "not_before": now - 5,
            "expires_at": now + 120,
            "members": [
                {**{field: identity[field] for field in (
                    "node_id", "node_rank", "boot_id", "overlay_ipv4", "wireguard_public_key_b64"
                )}, "image_hash_hex": "a" * 64, "tee_type": "tdx"}
                for identity in identities
            ],
        }
        payload_path = directory / "payload.json"
        payload_path.write_text(json.dumps(payload))
        envelope_path = directory / "membership.json"
        run(binary, "sign-membership", "--payload", str(payload_path), "--signing-key", str(signer),
            "--output", str(envelope_path))
        envelope = json.loads(envelope_path.read_text())
        encoded = base64.b64decode(envelope["payload_b64"], validate=True)
        assert encoded.startswith(b"cocoon/wg-membership/v1\0")
        message_path, signature_path = directory / "message.bin", directory / "signature.bin"
        message_path.write_bytes(encoded)
        signature_path.write_bytes(base64.b64decode(envelope["signature_b64"], validate=True))
        run("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_path), "-keyform", "DER",
            "-rawin", "-in", str(message_path), "-sigfile", str(signature_path))
        for node, config_path in zip(("a", "b"), configurations):
            verified = json.loads(run(binary, "verify-membership", "--config", str(config_path),
                                      "--membership", str(envelope_path), "--state-dir", str(directory / f"identity-{node}")))
            assert verified == payload

        original = envelope_path.read_text()
        tampered = dict(envelope)
        tampered["signature_b64"] = base64.b64encode(b"\0" * 64).decode()
        envelope_path.write_text(json.dumps(tampered))
        run(binary, "verify-membership", "--config", str(configurations[0]), "--membership", str(envelope_path),
            "--state-dir", str(directory / "identity-a"), code=1)
        envelope_path.write_text(original)
        run(binary, "verify-membership", "--config", str(configurations[0]), "--membership", str(envelope_path),
            "--state-dir", str(directory / "replacement-identity"), code=1)
        payload["not_before"], payload["expires_at"] = now - 180, now - 60
        payload_path.write_text(json.dumps(payload))
        expired_path = directory / "expired.json"
        run(binary, "sign-membership", "--payload", str(payload_path), "--signing-key", str(signer),
            "--output", str(expired_path))
        run(binary, "verify-membership", "--config", str(configurations[0]), "--membership", str(expired_path),
            "--state-dir", str(directory / "identity-a"), code=1)
        signer.chmod(0o644)
        run(binary, "sign-membership", "--payload", str(payload_path), "--signing-key", str(signer), code=1)
        signer.chmod(0o600)
        wrong_type = directory / "x25519.pem"
        run("openssl", "genpkey", "-algorithm", "X25519", "-out", str(wrong_type))
        wrong_type.chmod(0o600)
        run(binary, "sign-membership", "--payload", str(payload_path), "--signing-key", str(wrong_type), code=1)
        run(binary, "enroll", "--config", str(configurations[0]), "--state-dir", str(directory / "identity-a"),
            "--fake-tee", "true", code=1)
        run(binary, "check-config", "--config", str(configurations[0]), "--config", str(configurations[1]), code=1)
        run(binary, "--internal-quote", input_bytes=b"invalid-reportdata", code=1)
        run(binary, "--internal-verify", input_bytes=b"invalid-quote", code=1)
        # Never allow an admission flag to select synthetic verification.
        run(binary, "admit-peer", "--config", str(configurations[0]), "--membership", str(envelope_path),
            "--peer", "worker-b", "--fake-tee", "true", code=1)
        run(binary, "setup", "--config", str(configurations[0]), "--membership", str(envelope_path),
            "--fake-tee", "true", code=1)
        run(binary, "run", "--config", str(configurations[0]), "--membership", str(envelope_path),
            "--fake-tee", "true", code=1)
        run(binary, "cleanup", "--config", str(configurations[0]), "--membership", str(envelope_path), code=1)
        probe_state = directory / "unsupported-admission"
        probe = subprocess.run(
            [binary, "admit-peer", "--config", str(configurations[0]), "--membership", str(envelope_path),
             "--peer", "not-configured", "--state-dir", str(probe_state)],
            capture_output=True, timeout=15,
        )
        commands += 1
        assert probe.returncode == 1 and probe.stdout == b""
        if b"no real TDX/DCAP support" in probe.stderr:
            assert not probe_state.exists(), "Unsupported build created admission state"
            setup_state = directory / "unsupported-setup"
            run(binary, "setup", "--config", str(configurations[0]), "--membership", str(envelope_path),
                "--state-dir", str(setup_state), code=1)
            assert not setup_state.exists(), "Unsupported build created setup state"
            run_state = directory / "unsupported-run"
            run(binary, "run", "--config", str(configurations[0]), "--membership", str(envelope_path),
                "--state-dir", str(run_state), code=1)
            assert not run_state.exists(), "Unsupported build created supervisor state"
        else:
            assert b"Peer is not configured" in probe.stderr

    print(f"WireGuard CLI integration: {commands} commands passed, including independent OpenSSL verification")


if __name__ == "__main__":
    main()
