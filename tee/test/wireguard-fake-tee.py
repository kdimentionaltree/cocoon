#!/usr/bin/env python3
"""Run the real --no-tee admission CLI on loopback without TEE hardware or network mutations."""

import base64
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def main():
    binary = str(Path(sys.argv[1]).resolve())
    root = Path(__file__).resolve().parents[2]
    checks = 0

    def run(*args, code=0):
        nonlocal checks
        result = subprocess.run(args, capture_output=True, timeout=15)
        checks += 1
        assert result.returncode == code, result.stderr.decode(errors='replace')
        return result.stdout

    with tempfile.TemporaryDirectory(prefix='cocoon-wg-fake-cli-') as temporary:
        directory = Path(temporary)
        signer = directory / 'signer.pem'
        run('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(signer))
        signer.chmod(0o600)
        signer_key = base64.b64encode(run('openssl', 'pkey', '-in', str(signer), '-pubout', '-outform', 'DER')[-32:]).decode()
        configs, paths, states, offers = [], [], [], []
        # Keep both port reservations open until all ports are chosen.
        reservations = [socket.socket() for _ in range(2)]
        try:
            for sock in reservations: sock.bind(('127.0.0.1', 0))
            ports = [sock.getsockname()[1] for sock in reservations]
        finally:
            for sock in reservations: sock.close()
        for i, node in enumerate(('a', 'b')):
            config = json.loads((root / f'scripts/wireguard/worker-{node}.example.json').read_text())
            config['workload_policy_sha256'] = '1' * 64
            config['membership_signer_public_key_b64'] = signer_key
            config['attestation'] = {'type': 'fake_tee', 'image_policy': 'signed_membership'}
            config['cert_base_name'] = str(directory / node)
            config['admission_port'] = ports[i]
            config['peers'][0].update(endpoint_ipv4='127.0.0.1', admission_endpoint_port=ports[1 - i])
            config['timeouts']['startup_seconds'] = 4
            config['timeouts']['handshake_seconds'] = 3
            path = directory / f'{node}.json'; path.write_text(json.dumps(config))
            state = directory / f'state-{node}'
            run(binary, 'enroll', '--config', str(path), '--state-dir', str(state), code=1)
            assert not state.exists(), 'Missing --no-tee created debug identity'
            offer = json.loads(run(binary, 'enroll', '--no-tee', '--config', str(path), '--state-dir', str(state)))
            assert offer['requested_tee_type'] == 'fake_tee' and offer['attestation_status'] == 'synthetic'
            run(binary, 'check-config', '--no-tee', '--config', str(path), '--no-tee', code=1)
            real = dict(config, attestation={'type': 'tdx', 'image_policy': 'signed_membership'})
            real_path = directory / f'{node}-real.json'; real_path.write_text(json.dumps(real))
            run(binary, 'enroll', '--no-tee', '--config', str(real_path), '--state-dir', str(state), code=1)
            run(binary, 'enroll', '--config', str(real_path), '--state-dir', str(state), code=1)
            configs.append(config); paths.append(path); states.append(state); offers.append(offer)

        payload_path = directory / 'members.json'
        envelope_path = directory / 'grant.json'

        def prepare(sev_b=False, wrong_image=False):
            members = []
            for i, config in enumerate(configs):
                base = config['cert_base_name']; key = base + '_key.pem'
                run('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', key)
                Path(key).chmod(0o600)
                public = run('openssl', 'pkey', '-in', key, '-pubout', '-outform', 'DER')[-32:]
                claims = hashlib.sha512(public).digest()
                if sev_b and i == 1:
                    report = bytes(80) + claims + bytes(1040)
                    extensions = {100: claims, 101: report, 102: b'fake-vcek'}
                    image = hashlib.sha256(bytes(112)).hexdigest()
                else:
                    report = bytes(384) + claims + bytes(48)
                    extensions = {1: report, 2: public}
                    image = hashlib.sha256(bytes(448)).hexdigest()
                arguments = ['openssl', 'req', '-new', '-x509', '-key', key, '-out', base + '_cert.pem',
                             '-subj', '/CN=cocoon-fake-test', '-days', '1']
                for oid, value in extensions.items():
                    arguments.extend(['-addext', f'1.3.6.1.4.1.12345.{oid}=critical,DER:{value.hex()}'])
                run(*arguments)
                members.append({key: offers[i][key] for key in ('node_id', 'node_rank', 'boot_id',
                                'overlay_ipv4', 'wireguard_public_key_b64')})
                members[-1].update(tee_type='fake_tee', image_hash_hex='a' * 64 if wrong_image else image)
            now = int(time.time())
            payload = dict(format='cocoon-wireguard-membership-v1', cluster_id=configs[0]['cluster_id'],
                           workload_policy_sha256='1' * 64, generation=1, not_before=now - 1,
                           expires_at=now + 120, members=members)
            payload_path.write_text(json.dumps(payload))
            envelope_path.unlink(missing_ok=True)
            run(binary, 'sign-membership', '--payload', str(payload_path), '--signing-key', str(signer),
                '--output', str(envelope_path))
            return payload

        def pair(success):
            nonlocal checks
            def arguments(i):
                return [binary, 'admit-peer', '--config', str(paths[i]), '--state-dir', str(states[i]),
                        '--membership', str(envelope_path), '--peer', configs[1 - i]['node_id'], '--no-tee']
            server = subprocess.Popen(arguments(1), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                client = subprocess.run(arguments(0), capture_output=True, timeout=10)
                server_out, server_err = server.communicate(timeout=10)
            finally:
                if server.poll() is None:
                    server.kill(); server.communicate()
            checks += 2
            expected = 0 if success else 1
            assert client.returncode == server.returncode == expected, (client.stderr, server_err)
            if success:
                results = [json.loads(client.stdout), json.loads(server_out)]
                assert all(result['status'] == 'peer_admitted' and result['attestation_type'] == 'fake_tee'
                           and result['workload_ready'] is False for result in results)
                assert results[0]['membership_sha256'] == results[1]['membership_sha256']

        for sev_b in (False, True):
            payload = prepare(sev_b)
            for i in range(2):
                verified = json.loads(run(binary, 'verify-membership', '--config', str(paths[i]), '--no-tee',
                                         '--state-dir', str(states[i]), '--membership', str(envelope_path)))
                assert all(member['tee_type'] == 'fake_tee' for member in verified['members'])
            pair(True)
            payload['members'][0]['tee_type'] = 'tdx'; payload_path.write_text(json.dumps(payload))
            run(binary, 'sign-membership', '--payload', str(payload_path), '--signing-key', str(signer), code=1)
        prepare(wrong_image=True)
        pair(False)
    print(f'Fake-TEE CLI: {checks} commands passed, including actual loopback admission and mode rejection')


if __name__ == '__main__':
    main()
