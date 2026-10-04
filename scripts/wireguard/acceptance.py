#!/usr/bin/env python3
"""Bounded guest diagnostics and synthetic TCP/UDP traffic; never an attestation authority."""

import argparse
import base64
import json
import os
from pathlib import Path
import selectors
import socket
import stat
import struct
import subprocess
import time

STATE = Path('/run/cocoon-wireguard')
MAGIC = b'COCOON-WG-TEST-v1\0'
MAX_TCP = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON field')
        result[key] = value
    return result


def read_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'r') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Expected a regular JSON file')
        value = stream.read(1024 * 1024 + 1)
    require(len(value) <= 1024 * 1024, 'JSON exceeds size limit')
    result = json.loads(value, object_pairs_hook=unique_fields)
    require(isinstance(result, dict), 'Expected a JSON object')
    return result


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError('Acceptance deadline exceeded')
    return value


def command(arguments, deadline):
    result = subprocess.run(arguments, check=False, capture_output=True, text=True,
                            timeout=min(5, remaining(deadline)))
    require(result.returncode == 0, f'Diagnostic command failed: {Path(arguments[0]).name}')
    require(len(result.stdout) <= 1024 * 1024, 'Diagnostic output exceeds limit')
    return result.stdout


def unit(name, deadline):
    value = command(['/usr/bin/systemctl', 'show', name, '--no-pager',
                     '--property=ActiveState,SubState,MainPID,Type,BindsTo,After'], deadline)
    return dict(line.split('=', 1) for line in value.splitlines() if '=' in line)


def permissions(gate):
    result = {}
    for entry in gate['nftables']:
        if 'set' not in entry:
            continue
        body = entry['set']
        values = set()
        for element in body.get('elem', []):
            require(isinstance(element, dict) and set(element) == {'elem'}, 'Untimed permission element')
            item = element['elem']
            require(type(item.get('timeout')) is int and item['timeout'] > 0 and
                    type(item.get('expires')) is int and item['expires'] > 0, 'Non-expiring permission element')
            require(item['val'] not in values, 'Duplicate permission address')
            values.add(item['val'])
        result[body['name']] = values
    require(set(result) == {'active_peers', 'ready_node'}, 'Missing timed permission sets')
    return result


def inspect(config, path, expect, backend, deadline):
    # check-gate shares the daemon's exact static-policy comparison and never acquires the identity lock.
    flags = ['--no-tee'] if config['attestation']['type'] == 'fake_tee' else []
    gate = json.loads(command(['/usr/bin/cocoon-wireguard', 'check-gate', '--config', str(path), *flags], deadline))
    allowed = permissions(gate)
    overlay = unit('cocoon-wireguard.service', deadline)
    links = json.loads(command(['/usr/sbin/ip', '-d', '-j', 'link', 'show'], deadline))
    links = [link for link in links if link['ifname'] == config['interface']]
    consumers = ['cocoon-worker-runner.service']
    if backend:
        consumers.append(f'cocoon-{backend}.service')
    for name in consumers:
        consumer = unit(name, deadline)
        require('cocoon-wireguard.service' in consumer.get('BindsTo', '').split() and
                'cocoon-wireguard.service' in consumer.get('After', '').split(), 'Consumer lacks overlay dependency')
        if expect == 'closed':
            require(consumer.get('ActiveState') in ('inactive', 'failed'), 'Bound consumer is still active')
    if expect == 'closed':
        require(overlay.get('ActiveState') in ('inactive', 'failed'), 'Overlay is still active or restarting')
        require(not links and not allowed['ready_node'] and not allowed['active_peers'], 'Owned overlay is not closed')
        return {'expected': 'closed', 'gate_valid': True, 'interface_absent': True, 'consumers_stopped': consumers}

    status = read_json(STATE / 'status.json')
    now = time.time()
    require(status.get('format') == 'cocoon-wireguard-status-v1' and status.get('workload_ready') is True,
            'Status does not report workload readiness')
    require(status.get('attestation_type') == config['attestation']['type'], 'Status attestation mode mismatch')
    require(type(status.get('updated_at')) is int and 0 <= now - status['updated_at'] <= 5 and
            0 <= now - (STATE / 'status.json').stat().st_mtime <= 5, 'Status is stale or from a future clock')
    require(overlay.get('ActiveState') == 'active' and overlay.get('SubState') == 'running' and
            overlay.get('Type') == 'notify' and int(overlay.get('MainPID', '0')) > 0,
            'Overlay has no live notification-ready service')
    require(status['interface'] == config['interface'] and status['overlay_ipv4'] == config['overlay_ipv4'] and
            status['generation'] == config['generation'] and status['expires_at'] > now, 'Status context or lease mismatch')
    require(len(links) == 1, 'Overlay interface missing or duplicated')
    enrollment = read_json(STATE / 'enrollment.json')
    for field in ('cluster_id', 'workload_policy_sha256', 'generation', 'node_id', 'node_rank', 'overlay_ipv4'):
        require(enrollment[field] == config[field], 'Enrollment context mismatch')
    link = links[0]
    require(link.get('ifalias') == 'cocoon-wireguard:' + enrollment['boot_id'] and
            link.get('mtu') == config.get('mtu', 1400) and 'UP' in link.get('flags', []) and
            link.get('linkinfo', {}).get('info_kind') == 'wireguard', 'Overlay ownership/state mismatch')
    public = command(['/usr/bin/wg', 'show', config['interface'], 'public-key'], deadline).strip()
    require(public == enrollment['wireguard_public_key_b64'], 'Kernel local public key mismatch')
    expected = {}
    configured = {peer['node_id']: peer for peer in config['peers']}
    require(len(status['peers']) == len(configured), 'Status peer count mismatch')
    seen = set()
    required_ips = set()
    for peer in status['peers']:
        require(peer['node_id'] in configured and peer['node_id'] not in seen, 'Unexpected or duplicate status peer')
        seen.add(peer['node_id'])
        intended = configured[peer['node_id']]
        require(peer['overlay_ipv4'] == intended['overlay_ipv4'] and peer['required'] == intended['required'],
                'Status peer allocation mismatch')
        if intended['required']:
            require(peer['state'] == 'healthy' and peer['lease_remaining_ms'] > 0, 'Required peer is unhealthy')
            required_ips.add(peer['overlay_ipv4'])
        if peer['state'] == 'healthy':
            key = peer['wireguard_public_key_b64']
            require(len(base64.b64decode(key, validate=True)) == 32 and key not in expected, 'Invalid peer public key')
            expected[key] = peer['overlay_ipv4'] + '/32'
            routes = json.loads(command(['/usr/sbin/ip', '-j', '-4', 'route', 'get', peer['overlay_ipv4']], deadline))
            require(len(routes) == 1 and routes[0].get('dev') == config['interface'] and
                    routes[0].get('prefsrc', routes[0].get('src')) == config['overlay_ipv4'], 'Peer route bypasses overlay')
    actual = {}
    for line in command(['/usr/bin/wg', 'show', config['interface'], 'allowed-ips'], deadline).splitlines():
        key, value = line.split(maxsplit=1)
        require(key not in actual, 'Duplicate kernel peer')
        actual[key] = value.strip()
    require(actual == expected and expected, 'Kernel peer keys/AllowedIPs differ from healthy admitted peers')
    healthy_ips = {ip.split('/')[0] for ip in expected.values()}
    require(allowed['ready_node'] == {config['overlay_ipv4']} and required_ips <= allowed['active_peers'] and
            allowed['active_peers'] <= healthy_ips, 'Kernel readiness permissions mismatch')
    return {'expected': 'ready', 'gate_valid': True, 'node_id': config['node_id'],
            'membership_sha256': status['membership_sha256'], 'expires_at': status['expires_at'],
            'healthy_peers': len(expected), 'consumer_dependencies': consumers}


def bound_socket(config, kind, port=0):
    sock = socket.socket(socket.AF_INET, kind)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, config['interface'].encode() + b'\0')
        if kind == socket.SOCK_DGRAM:
            # Linux IP_MTU_DISCOVER=10, IP_PMTUDISC_DO=2: reject accidental inner IPv4 fragmentation.
            sock.setsockopt(socket.IPPROTO_IP, 10, 2)
        sock.bind((config['overlay_ipv4'], port))
        return sock
    except BaseException:
        sock.close()
        raise


def receive_exact(sock, size, deadline):
    result = bytearray()
    while len(result) < size:
        sock.settimeout(min(3, remaining(deadline)))
        value = sock.recv(size - len(result))
        require(value, 'Truncated echo frame')
        result.extend(value)
    return bytes(result)


def echo_tcp(connection, deadline):
    size = struct.unpack('!I', receive_exact(connection, 4, deadline))[0]
    require(len(MAGIC) + 32 <= size <= MAX_TCP, 'Invalid echo frame size')
    payload = receive_exact(connection, size, deadline)
    require(payload.startswith(MAGIC), 'Unexpected test protocol')
    connection.settimeout(min(3, remaining(deadline)))
    connection.sendall(payload)


def serve(config, port, seconds):
    deadline = time.monotonic() + seconds
    permitted = {peer['overlay_ipv4'] for peer in config['peers']}
    max_udp = config.get('mtu', 1400) - 28
    counts = {'tcp': 0, 'udp': 0}
    with bound_socket(config, socket.SOCK_STREAM, port) as tcp, \
            bound_socket(config, socket.SOCK_DGRAM, port) as udp, selectors.DefaultSelector() as selector:
        tcp.listen(4)
        tcp.setblocking(False); udp.setblocking(False)
        selector.register(tcp, selectors.EVENT_READ); selector.register(udp, selectors.EVENT_READ)
        print(json.dumps({'event': 'listening', 'ipv4': config['overlay_ipv4'], 'port': port}), flush=True)
        while time.monotonic() < deadline:
            for key, _ in selector.select(max(0, min(0.25, deadline - time.monotonic()))):
                if key.fileobj is udp:
                    payload, address = udp.recvfrom(max_udp + 1)
                    if address[0] in permitted and len(MAGIC) + 32 <= len(payload) <= max_udp and payload.startswith(MAGIC):
                        udp.sendto(payload, address); counts['udp'] += 1
                else:
                    connection, address = tcp.accept()
                    with connection:
                        if address[0] not in permitted:
                            continue
                        try:
                            echo_tcp(connection, deadline)
                            counts['tcp'] += 1
                        except (OSError, ValueError):
                            pass  # A malformed/slow request cannot extend the overall server deadline.
    return {'echoes': counts, 'seconds': seconds}


def exchange(config, peer, port, count, seconds):
    deadline = time.monotonic() + seconds
    results = {}
    for name, kind, size in (('udp', socket.SOCK_DGRAM, config.get('mtu', 1400) - 28),
                             ('tcp', socket.SOCK_STREAM, 256 * 1024)):
        latencies = []
        for _ in range(count):
            payload = MAGIC + os.urandom(size - len(MAGIC))
            start = time.monotonic()
            with bound_socket(config, kind) as sock:
                sock.settimeout(min(3, remaining(deadline)))
                sock.connect((peer['overlay_ipv4'], port))
                sock.settimeout(min(3, remaining(deadline)))
                sock.sendall(payload if name == 'udp' else struct.pack('!I', len(payload)) + payload)
                sock.settimeout(min(3, remaining(deadline)))
                received = sock.recv(size + 1) if name == 'udp' else receive_exact(sock, size, deadline)
                require(received == payload, 'Echo payload mismatch')
            latencies.append((time.monotonic() - start) * 1000)
        results[name] = {'exchanges': count, 'payload_bytes': size,
                         'rtt_ms_min': round(min(latencies), 3), 'rtt_ms_max': round(max(latencies), 3)}
    return {'peer': peer['node_id'], 'traffic': results}


def require_guest(config):
    require(os.geteuid() == 0, 'Acceptance tooling requires guest root')
    fake = config['attestation']['type'] == 'fake_tee'
    no_tee = 'cocoon_no_tee' in Path('/proc/cmdline').read_text().split()
    require(fake == no_tee, 'WireGuard attestation mode must match the guest --no-tee boot flag')
    require(fake or Path('/dev/tdx_guest').exists(), 'Live acceptance requires an actual TDX guest')


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('/run/spec/wireguard-config.json'))
    sub = parser.add_subparsers(dest='operation', required=True)
    check = sub.add_parser('inspect', help='Read-only readiness or completed-cleanup checks')
    check.add_argument('--expect', choices=['ready', 'closed'], default='ready')
    check.add_argument('--backend', choices=['sglang', 'vllm'])
    check.add_argument('--wait', type=int, default=0)
    server = sub.add_parser('serve', help='Temporary device-bound synthetic TCP/UDP echo server')
    server.add_argument('--seconds', type=int, default=120)
    server.add_argument('--port', type=int, default=29501)
    client = sub.add_parser('exchange', help='Verify TCP and MTU-sized UDP traffic to one allocated peer')
    client.add_argument('--peer', required=True)
    client.add_argument('--seconds', type=int, default=30)
    client.add_argument('--port', type=int, default=29501)
    client.add_argument('--count', type=int, default=4)
    args = parser.parse_args()
    require(0 <= getattr(args, 'wait', 0) <= 300, 'wait must be 0–300 seconds')
    require(1 <= getattr(args, 'seconds', 1) <= 300, 'seconds must be 1–300')
    require(1 <= getattr(args, 'count', 1) <= 100, 'count must be 1–100')
    port = getattr(args, 'port', 29501)
    require(1024 <= port <= 65535 and port not in (51822, 51823, 8000), 'Invalid/reserved test port')
    return args


def main():
    args = parse_args()
    config = read_json(args.config)
    require_guest(config)
    flags = ['--no-tee'] if config['attestation']['type'] == 'fake_tee' else []
    command(['/usr/bin/cocoon-wireguard', 'check-config', '--config', str(args.config), *flags], time.monotonic() + 5)
    if args.operation == 'inspect':
        deadline = time.monotonic() + max(args.wait, 20)
        retry_end = time.monotonic() + args.wait
        while True:
            try:
                result = inspect(config, args.config, args.expect, args.backend, deadline)
                break
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                if time.monotonic() >= retry_end:
                    raise
                time.sleep(min(0.25, remaining(deadline)))
    else:
        require(args.port not in (config['listen_port'], config['admission_port']), 'Test port conflicts with overlay listener')
        inspect(config, args.config, 'ready', None, time.monotonic() + 20)
        if args.operation == 'serve':
            result = serve(config, args.port, args.seconds)
        else:
            peer = next((peer for peer in config['peers'] if peer['node_id'] == args.peer), None)
            require(peer is not None, 'Unknown allocated peer')
            result = exchange(config, peer, args.port, args.count, args.seconds)
    print(json.dumps({'format': 'cocoon-wireguard-acceptance-v1', 'operation': args.operation,
                      'attestation_type': config['attestation']['type'],
                      'observed_at': int(time.time()), 'result': result}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(f'WireGuard acceptance failed: {error}')
