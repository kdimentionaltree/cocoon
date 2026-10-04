#!/usr/bin/env python3
"""Local acceptance-tool checks. Socket tests use loopback; no host policy or services change."""

import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/wireguard' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


acceptance = load('wireguard_acceptance_test', 'acceptance.py')
collective = load('wireguard_collective_test', 'collective.py')


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cocoon-wg-acceptance-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = json.loads((ROOT / 'scripts/wireguard/worker-a.example.json').read_text())
        self.config['workload_policy_sha256'] = '1' * 64
        self.config['membership_signer_public_key_b64'] = base64.b64encode(b'a' * 32).decode()
        self.path = self.root / 'config.json'; self.path.write_text(json.dumps(self.config))
        self.key = base64.b64encode(b'b' * 32).decode()
        self.enrollment = {**self.config, 'boot_id': 'b' * 64, 'wireguard_public_key_b64': self.key}
        self.peer_key = base64.b64encode(b'c' * 32).decode()
        self.status = {'format': 'cocoon-wireguard-status-v1', 'workload_ready': True, 'updated_at': int(time.time()),
                       'attestation_type': 'tdx',
                       'interface': 'wg0', 'overlay_ipv4': '10.77.0.1', 'generation': 1, 'expires_at': int(time.time()) + 120,
                       'membership_sha256': 'c' * 64,
                       'peers': [{'node_id': 'worker-b', 'overlay_ipv4': '10.77.0.2', 'required': True,
                                  'state': 'healthy', 'lease_remaining_ms': 10000, 'wireguard_public_key_b64': self.peer_key}]}
        self.gate = {'nftables': [{'set': {'name': name, 'elem': [
            {'elem': {'val': address, 'timeout': 10, 'expires': 9}}]}} for name, address in
            [('active_peers', '10.77.0.2'), ('ready_node', '10.77.0.1')]]}
        self.links = [{'ifname': 'wg0', 'ifalias': 'cocoon-wireguard:' + 'b' * 64, 'mtu': 1400,
                       'flags': ['UP'], 'linkinfo': {'info_kind': 'wireguard'}}]
        self.route = [{'dev': 'wg0', 'prefsrc': '10.77.0.1'}]
        self.service = {'ActiveState': 'active', 'SubState': 'running', 'Type': 'notify', 'MainPID': '42',
                        'BindsTo': 'cocoon-wireguard.service', 'After': 'cocoon-wireguard.service'}
        state = patch.object(acceptance, 'STATE', self.root); state.start(); self.addCleanup(state.stop)
        self.refresh()

    def refresh(self):
        (self.root / 'status.json').write_text(json.dumps(self.status))
        (self.root / 'enrollment.json').write_text(json.dumps(self.enrollment))

    def inspect(self, expect='ready'):
        def command(args, deadline):
            if args[0] == '/usr/bin/cocoon-wireguard': return json.dumps(self.gate)
            if args[0] == '/usr/sbin/ip': return json.dumps(self.route if 'route' in args else self.links)
            if args[-1] == 'public-key': return self.key + '\n'
            if args[-1] == 'allowed-ips': return self.peer_key + '\t10.77.0.2/32\n'
            raise AssertionError(f'Unexpected operation: {args}')
        with patch.object(acceptance, 'command', side_effect=command), patch.object(acceptance, 'unit', return_value=self.service):
            return acceptance.inspect(self.config, self.path, expect, 'sglang', time.monotonic() + 5)

    def test_ready_combines_live_process_status_routes_keys_and_gate(self):
        self.assertEqual(self.inspect()['healthy_peers'], 1)

    def test_stale_status_and_absent_live_service_fail(self):
        self.status['updated_at'] -= 20; self.refresh()
        with self.assertRaisesRegex(ValueError, 'stale'): self.inspect()
        self.status['updated_at'] = int(time.time()); self.refresh()
        self.service['ActiveState'] = 'inactive'
        with self.assertRaisesRegex(ValueError, 'live'): self.inspect()

    def test_foreign_interface_and_underlay_route_fail(self):
        self.links[0]['ifalias'] = 'foreign'
        with self.assertRaisesRegex(ValueError, 'ownership'): self.inspect()
        self.links[0]['ifalias'] = 'cocoon-wireguard:' + 'b' * 64
        self.route[0]['dev'] = 'eth0'
        with self.assertRaisesRegex(ValueError, 'bypasses'): self.inspect()

    def test_consumer_binding_and_peer_allocation_fail(self):
        self.service['BindsTo'] = ''
        with self.assertRaisesRegex(ValueError, 'dependency'): self.inspect()
        self.service['BindsTo'] = 'cocoon-wireguard.service'
        self.status['peers'][0]['overlay_ipv4'] = '10.77.0.3'; self.refresh()
        with self.assertRaisesRegex(ValueError, 'allocation'): self.inspect()

    def test_unhealthy_peer_and_indefinite_permission_fail(self):
        self.status['peers'][0]['state'] = 'not_admitted'; self.refresh()
        with self.assertRaisesRegex(ValueError, 'unhealthy'): self.inspect()
        self.status['peers'][0]['state'] = 'healthy'; self.refresh()
        del self.gate['nftables'][0]['set']['elem'][0]['elem']['expires']
        with self.assertRaisesRegex(ValueError, 'Non-expiring'): self.inspect()

    def test_unexpected_permission_address_fails(self):
        self.gate['nftables'][0]['set']['elem'][0]['elem']['val'] = '10.77.0.3'
        with self.assertRaisesRegex(ValueError, 'permissions'): self.inspect()

    def test_closed_requires_stopped_consumers_no_interface_and_empty_sets(self):
        self.service['ActiveState'] = 'inactive'
        with self.assertRaisesRegex(ValueError, 'not closed'): self.inspect('closed')
        self.links = []
        for entry in self.gate['nftables']: entry['set']['elem'] = []
        self.assertTrue(self.inspect('closed')['interface_absent'])
        self.service['ActiveState'] = 'activating'
        with self.assertRaises(ValueError): self.inspect('closed')

    def test_json_duplicate_oversized_and_symlink_fail(self):
        path = self.root / 'invalid.json'
        for value in ('{"a":1,"a":2}', 'x' * (1024 * 1024 + 1), '[]'):
            path.write_text(value)
            with self.assertRaises(ValueError): acceptance.read_json(path)
        path.unlink(); path.symlink_to(self.path)
        with self.assertRaises(OSError): acceptance.read_json(path)

    def test_guest_guard_requires_explicit_matching_debug_boot(self):
        fake = copy.deepcopy(self.config); fake['attestation']['type'] = 'fake_tee'
        with patch.object(acceptance.os, 'geteuid', return_value=0), patch.object(Path, 'exists', return_value=False):
            with patch.object(Path, 'read_text', return_value='quiet'):
                with self.assertRaisesRegex(ValueError, 'actual TDX'): acceptance.require_guest(self.config)
                with self.assertRaisesRegex(ValueError, 'boot flag'): acceptance.require_guest(fake)
            with patch.object(Path, 'read_text', return_value='quiet cocoon_no_tee'):
                acceptance.require_guest(fake)
                with self.assertRaisesRegex(ValueError, 'boot flag'): acceptance.require_guest(self.config)

    def test_fake_readiness_requires_matching_status_mode(self):
        self.config['attestation']['type'] = 'fake_tee'
        with self.assertRaisesRegex(ValueError, 'attestation mode'): self.inspect()
        self.status['attestation_type'] = 'fake_tee'; self.refresh()
        self.assertEqual(self.inspect()['healthy_peers'], 1)

    def test_sockets_bind_device_and_source_and_disable_udp_fragmentation(self):
        class Socket:
            def __init__(self): self.options = []; self.bound = None
            def setsockopt(self, *args): self.options.append(args)
            def bind(self, target): self.bound = target
        sock = Socket()
        with patch.object(acceptance.socket, 'socket', return_value=sock):
            self.assertIs(acceptance.bound_socket(self.config, socket.SOCK_DGRAM), sock)
        self.assertIn((socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'wg0\0'), sock.options)
        self.assertIn((socket.IPPROTO_IP, 10, 2), sock.options)
        self.assertEqual(sock.bound, ('10.77.0.1', 0))

    def test_tcp_oversized_and_truncated_frames_fail(self):
        for frame in (struct.pack('!I', 2 ** 30), struct.pack('!I', 100) + b'short'):
            a, b = socket.socketpair()
            with a, b:
                b.sendall(frame); b.shutdown(socket.SHUT_WR)
                with self.assertRaises(ValueError): acceptance.echo_tcp(a, time.monotonic() + 1)

    def test_stalled_tcp_has_whole_operation_deadline(self):
        a, b = socket.socketpair()
        with a, b:
            start = time.monotonic()
            with self.assertRaises(TimeoutError): acceptance.echo_tcp(a, start + 0.1)
            self.assertLess(time.monotonic() - start, 0.5)

    def test_real_loopback_tcp_udp_echo_and_server_expiry(self):
        a = copy.deepcopy(self.config); b = copy.deepcopy(self.config)
        a['overlay_ipv4'] = '127.0.0.1'; a['peers'][0]['overlay_ipv4'] = '127.0.0.2'
        b['overlay_ipv4'] = '127.0.0.2'; b['peers'][0]['overlay_ipv4'] = '127.0.0.1'
        def socket_for(config, kind, port=0):
            sock = socket.socket(socket.AF_INET, kind)
            sock.bind((config['overlay_ipv4'], port))
            return sock
        with socket_for(b, socket.SOCK_STREAM) as reserve: port = reserve.getsockname()[1]
        ready = threading.Event(); outcome = []; errors = []
        def printed(*args, **kwargs): ready.set()
        def server():
            try: outcome.append(acceptance.serve(b, port, 1))
            except BaseException as error: errors.append(error); ready.set()
        with patch.object(acceptance, 'bound_socket', side_effect=socket_for), patch('builtins.print', side_effect=printed):
            thread = threading.Thread(target=server); thread.start()
            try:
                self.assertTrue(ready.wait(1)); self.assertFalse(errors)
                result = acceptance.exchange(a, a['peers'][0], port, 3, 1)
            finally: thread.join(3)
        self.assertFalse(thread.is_alive()); self.assertFalse(errors)
        self.assertEqual(outcome[0]['echoes'], {'tcp': 3, 'udp': 3})
        self.assertEqual(result['traffic']['udp']['payload_bytes'], 1372)

    def test_collective_layout_and_exact_transport_selection(self):
        self.assertEqual(collective.layout(self.config), (0, 'wg0', '10.77.0.1'))
        environment = collective.transport_environment('wg0')
        self.assertEqual(environment['NCCL_NET'], 'Socket')
        self.assertEqual(environment['NCCL_SOCKET_IFNAME'], '=wg0')
        self.assertEqual(environment['NCCL_OOB_NET_ENABLE'], '0')
        self.config['peers'][0]['required'] = False
        with self.assertRaises(ValueError): collective.layout(self.config)

    def test_collective_store_listens_only_on_overlay_address(self):
        # Exercise a real overlay-address listener; only privileged device binding and PyTorch are substituted.
        native_socket = socket.socket
        class DeviceSocket(native_socket):
            def setsockopt(self, level, option, value):
                if option != socket.SO_BINDTODEVICE: super().setsockopt(level, option, value)
        addresses = []
        class Dist:
            @staticmethod
            def TCPStore(*args, **kwargs):
                self.assertFalse(kwargs['use_libuv'])
                with native_socket(fileno=kwargs['master_listen_fd']) as listener:
                    addresses.append(listener.getsockname())
                return 'store'
        config = copy.deepcopy(self.config); config['overlay_ipv4'] = '127.0.0.1'
        with patch.object(collective.socket, 'socket', DeviceSocket):
            self.assertEqual(collective.make_store(Dist, config, '127.0.0.1', 0, 1), 'store')
        self.assertEqual(addresses[0][0], '127.0.0.1'); self.assertGreater(addresses[0][1], 0)

    def test_collective_missing_pytorch_is_explicit_failure(self):
        args = type('Args', (), {'backend': 'gloo'})()
        with patch.dict(sys.modules, {'torch': None}):
            with self.assertRaisesRegex(ValueError, 'PyTorch installed'): collective.worker(args, self.config)


if __name__ == '__main__':
    unittest.main()
