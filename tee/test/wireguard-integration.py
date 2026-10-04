#!/usr/bin/env python3
"""Check guest/launcher integration without starting services or changing host networking."""

import base64
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else ROOT / 'build/tee/cocoon-wireguard'
REAL_RUN = subprocess.run


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


launch = load('wireguard_launch_test', ROOT / 'scripts/cocoon-launch')
guest = load('wireguard_guest_test', ROOT / 'reprodebian/cocoon-init/cocoon-wireguard-prepare')
modules = load('wireguard_modules_test', ROOT / 'reprodebian/pkg-aux/wireguard-modules.py')


def config():
    result = json.loads((ROOT / 'scripts/wireguard/worker-a.example.json').read_text())
    result['workload_policy_sha256'] = '1' * 64
    result['membership_signer_public_key_b64'] = base64.b64encode(bytes.fromhex(
        'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')).decode()
    return result


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cocoon-wg-integration-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.spec = self.root / 'spec'
        self.spec.mkdir()
        self.configuration = self.spec / 'wireguard-config.json'
        self.configuration.write_text(json.dumps(config()))

    def launch_config(self, **kwargs):
        result = launch.Config('worker', str(self.spec), 'test-owner', instance=1, tcp_ports=[12000],
                               ssh_port=12005, prepared_spec_dir=str(self.root / 'prepared'), **kwargs)
        launch.configure_wireguard(result)
        return result

    def test_forwarding_offsets_and_qemu(self):
        cfg = self.launch_config()
        self.assertIn(('udp', 51830, 51820), launch.network_forwardings(cfg))
        self.assertIn(('tcp', 51831, 51821), launch.network_forwardings(cfg))
        image = self.root / 'image'; image.mkdir()
        (image / 'image.cmdline').write_text('quiet')
        (image / 'OVMF.fd').touch()
        cfg.image_dir = str(image); cfg.print_only = True
        cfg.cpus = 1; cfg.ram = '1M'; cfg.vsock_cid = 6
        cfg.persistent = str(image / 'persistent.img'); Path(cfg.persistent).touch()
        output = io.StringIO()
        with patch.object(launch, 'this_cpu_vendor', return_value=launch.CPUVendor.Intel), contextlib.redirect_stdout(output):
            launch.run_qemu(cfg)
        self.assertIn('hostfwd=udp::51830-:51820', output.getvalue())
        self.assertIn('hostfwd=tcp::51831-:51821', output.getvalue())
        self.assertIn('host UDP 51830 -> guest UDP 51820', output.getvalue())

    def test_custom_ports_and_collision_rejection(self):
        cfg = self.launch_config(wireguard_udp_port=52000, wireguard_admission_port=52001)
        self.assertIn(('udp', 52010, 51820), launch.network_forwardings(cfg))
        for field, value in [('wireguard_admission_port', 12000), ('wireguard_udp_port', 65535), ('instance', -1)]:
            bad = copy.deepcopy(cfg); setattr(bad, field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                launch.network_forwardings(bad)
        cfg.udp_ports = [51820]
        with self.assertRaises(ValueError): launch.network_forwardings(cfg)

    def test_opt_in_and_no_tee_rejection(self):
        self.configuration.unlink()
        cfg = launch.Config('worker', str(self.spec), 'owner', tcp_ports=[12000])
        launch.configure_wireguard(cfg)
        self.assertEqual(launch.network_forwardings(cfg), [('tcp', 12000, 12000)])
        cfg.wireguard_udp_port = 51820
        with self.assertRaises(ValueError): launch.configure_wireguard(cfg)
        self.configuration.write_text(json.dumps(config()))
        for kind, no_tee in [('proxy', False), ('worker', True)]:
            cfg = launch.Config(kind, str(self.spec), 'owner', no_tee=no_tee)
            with self.assertRaises(ValueError): launch.configure_wireguard(cfg)

    def test_ini_and_measured_backend_preparation(self):
        ini = self.root / 'worker.ini'
        ini.write_text('[node]\ntype=worker\nowner_address=owner\ninstance=2\nbackend=vllm\n'
                       f'spec={self.spec}\nwireguard_config={self.configuration}\nwireguard_udp_port=52000\n')
        with patch.object(sys, 'argv', ['cocoon-launch', '--spec', str(self.spec), str(ini)]):
            cfg = launch.load_config_from_file(launch.parse_args())
        self.assertEqual(cfg.backend, 'vllm')
        self.assertIn(('udp', 52020, 51820), launch.network_forwardings(cfg))
        cfg.prepared_spec_dir = str(self.root / 'prepared')
        cfg.ton_config_base = None; cfg.ton_config = None; cfg.fake_ton = True
        (self.spec / 'init').write_text('#!/bin/bash\nsystemctl start test.service\n')
        with patch.object(cfg, 'get_runtime_vars', return_value={}), contextlib.redirect_stdout(io.StringIO()):
            launch.prepare_spec(cfg)
        prepared = Path(cfg.prepared_spec_dir)
        self.assertEqual((prepared / 'inference-backend').read_text(), 'vllm\n')
        self.assertEqual(json.loads((prepared / 'wireguard-config.json').read_text()), config())

    def guest_fixture(self, override=None):
        self.render_override = override
        self.rendered = self.root / 'rendered'; self.rendered.mkdir()
        self.state = self.root / 'state'
        self.units = self.root / 'units'
        self.membership = self.root / 'runtime/cluster-membership.json'
        self.calls = []
        self.rules = set()
        for backend in ('sglang', 'vllm'):
            content = (ROOT / f'spec/spec-worker/cocoon-{backend}.service').read_text().replace('$MODEL_NAME', 'fixture-model')
            (self.rendered / f'cocoon-{backend}.service').write_text(content)
        for name, value in [('SPEC', self.spec), ('RENDERED', self.rendered), ('STATE', self.state),
                            ('UNITS', self.units), ('MEMBERSHIP', self.membership)]:
            patcher = patch.object(guest, name, value); patcher.start(); self.addCleanup(patcher.stop)
        hardware = patch.object(guest, 'require_tdx'); hardware.start(); self.addCleanup(hardware.stop)

        def fake_run(arguments, **kwargs):
            self.calls.append(arguments)
            if arguments[0] == '/usr/bin/cocoon-render-config':
                value = json.loads(self.configuration.read_text())
                if self.render_override: value = self.render_override(value)
                (self.rendered / 'wireguard-config.json').write_text(json.dumps(value))
            elif arguments[0] == '/usr/bin/cocoon-wireguard':
                if arguments[1] == 'cleanup':
                    self.state.mkdir(mode=0o700, exist_ok=True)
                else:
                    args = [str(BINARY), *arguments[1:]]
                    if arguments[1] in ('enroll', 'verify-membership'):
                        args.extend(['--state-dir', str(self.state)])
                    if arguments[1] == 'verify-membership': kwargs['stderr'] = subprocess.PIPE
                    return REAL_RUN(args, **kwargs)
            elif arguments[0] == '/usr/sbin/iptables':
                action = arguments[3]; rule = tuple(arguments[5:])
                if action == '-C':
                    return subprocess.CompletedProcess(arguments, 0 if rule in self.rules else 1)
                if action == '-I': self.rules.add(rule)
                if action == '-D': self.rules.remove(rule)
            elif arguments[0] not in ('/usr/sbin/modprobe', '/usr/bin/systemctl'):
                raise AssertionError(f'Unexpected external action: {arguments}')
            return subprocess.CompletedProcess(arguments, 0, stdout='')

        runner = patch.object(guest.subprocess, 'run', side_effect=fake_run); runner.start(); self.addCleanup(runner.stop)

    def test_guest_configures_both_backends_and_cleanup(self):
        self.guest_fixture()
        for backend in ('sglang', 'vllm'):
            with contextlib.redirect_stdout(io.StringIO()): guest.configure(backend)
            text = (self.units / f'cocoon-{backend}.service.d/20-wireguard.conf').read_text()
            self.assertIn('BindsTo=cocoon-wireguard.service', text)
            self.assertIn('--network=host', text)
            self.assertIn('NCCL_SOCKET_IFNAME==wg0', text)
            self.assertIn('NCCL_NET=Socket', text)
            self.assertNotIn('-p 8000:8000', text)
        self.assertEqual(len(self.rules), 3)
        self.assertEqual((self.state / 'enrollment.json').stat().st_mode & 0o777, 0o600)
        self.assertIn('COCOON_OVERLAY_IPV4=10.77.0.1', (self.state / 'workload.env').read_text())
        actions = [args[1] for args in self.calls if args[0] == '/usr/bin/cocoon-wireguard']
        self.assertIn('cleanup', actions)
        first_cleanup = next(i for i, args in enumerate(self.calls) if args[:2] == ['/usr/bin/cocoon-wireguard', 'cleanup'])
        first_insert = next(i for i, args in enumerate(self.calls) if args[0] == '/usr/sbin/iptables' and '-I' in args)
        self.assertLess(first_cleanup, first_insert)
        guest.cleanup(config())
        self.assertFalse(self.rules)
        guest.cleanup(config())  # Exact-rule deletion remains idempotent.

    def test_runtime_can_only_change_endpoints(self):
        def hints(value):
            value['peers'][0]['endpoint_ipv4'] = '198.51.100.25'
            value['peers'][0]['endpoint_port'] = '51830'
            return value
        self.guest_fixture(hints)
        result = guest.render_config()
        self.assertEqual(result['peers'][0]['endpoint_port'], 51830)
        self.assertEqual(result['peers'][0]['endpoint_ipv4'], '198.51.100.25')

    def test_runtime_policy_substitution_rejected(self):
        self.guest_fixture()
        for field, new in [('membership_signer_public_key_b64', base64.b64encode(b'k' * 32).decode()),
                           ('workload_policy_sha256', '2' * 64), ('generation', 2), ('node_rank', 1),
                           ('overlay_ipv4', '10.77.0.3'), ('listen_port', 51830),
                           ('attestation', {'type': 'tdx', 'image_policy': 'any'})]:
            def substitute(value):
                value[field] = new
                return value
            self.render_override = substitute
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'authorization policy'):
                guest.render_config()
        def change_required(value):
            value['peers'][0]['required'] = False
            return value
        self.render_override = change_required
        with self.assertRaisesRegex(ValueError, 'authorization policy'): guest.render_config()
        self.assertFalse(any(args[0] == '/usr/sbin/iptables' for args in self.calls))

    def test_bootstrap_wait_is_bounded_and_invalid_grant_rejected(self):
        self.guest_fixture()
        guest.render_config()
        with patch.object(guest.time, 'monotonic', side_effect=[0, 61]), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'delivery deadline'): guest.wait_membership()
        self.membership.parent.mkdir()
        self.membership.write_text('{}')
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subprocess.CalledProcessError): guest.wait_membership()
        self.assertFalse(any('start' in args for args in self.calls if args[0] == '/usr/bin/systemctl'))

    def test_worker_unit_has_no_specialization_cycle(self):
        unit = (ROOT / 'scripts/wireguard/systemd/cocoon-wireguard.service').read_text()
        self.assertNotIn('After=spec.service', unit)
        self.assertIn('--membership /mnt/spec/runtime/cluster-membership.json', unit)
        self.assertNotIn('cocoon-wireguard.service', (ROOT / 'reprodebian/mkosi.postinst').read_text())

    def test_bootstrap_accepts_only_a_current_signed_guest_identity(self):
        self.guest_fixture()
        guest.render_config()
        with contextlib.redirect_stdout(io.StringIO()): guest.prepare_network(config())
        a = json.loads((self.state / 'enrollment.json').read_text())
        b_config = json.loads((ROOT / 'scripts/wireguard/worker-b.example.json').read_text())
        b_config['workload_policy_sha256'] = config()['workload_policy_sha256']
        b_config['membership_signer_public_key_b64'] = config()['membership_signer_public_key_b64']
        b_path = self.root / 'b.json'; b_path.write_text(json.dumps(b_config))
        result = REAL_RUN([str(BINARY), 'enroll', '--config', str(b_path), '--state-dir', str(self.root / 'state-b')],
                          check=True, capture_output=True, text=True)
        b = json.loads(result.stdout)
        pem = self.root / 'signer.pem'
        private_der = bytes.fromhex('302e020100300506032b657004220420' +
                                    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
        REAL_RUN(['openssl', 'pkey', '-inform', 'DER', '-out', str(pem)], input=private_der,
                 check=True, capture_output=True)
        pem.chmod(0o600)
        now = int(time.time())
        payload = dict(format='cocoon-wireguard-membership-v1', cluster_id=a['cluster_id'],
                       workload_policy_sha256=a['workload_policy_sha256'], generation=1,
                       not_before=now - 5, expires_at=now + 120, members=[])
        for identity in (a, b):
            payload['members'].append({**{name: identity[name] for name in
                ('node_id', 'node_rank', 'boot_id', 'overlay_ipv4', 'wireguard_public_key_b64')},
                'tee_type': 'tdx', 'image_hash_hex': 'a' * 64})
        source = self.root / 'payload.json'; source.write_text(json.dumps(payload))
        self.membership.parent.mkdir()
        REAL_RUN([str(BINARY), 'sign-membership', '--payload', str(source), '--signing-key', str(pem),
                  '--output', str(self.membership)], check=True, capture_output=True)
        with contextlib.redirect_stdout(io.StringIO()): guest.wait_membership()
        self.assertTrue(any('--membership' in args and str(self.membership) in args for args in self.calls))
        envelope = json.loads(self.membership.read_text())
        envelope['signature_b64'] = base64.b64encode(b'\0' * 64).decode()
        self.membership.write_text(json.dumps(envelope))
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subprocess.CalledProcessError): guest.wait_membership()

    def test_kernel_dependency_metadata_and_pruning(self):
        kernel = self.root / 'kernel'; kernel.mkdir()
        files = ['kernel/drivers/net/wireguard/wireguard.ko.xz', 'kernel/net/ipv4/udp_tunnel.ko.xz',
                 'kernel/lib/crypto/libcurve25519.ko.xz', 'kernel/net/netfilter/nf_tables.ko.xz']
        for name in files:
            path = kernel / name; path.parent.mkdir(parents=True, exist_ok=True); path.touch()
        (kernel / 'modules.dep').write_text(f'{files[0]}: {files[1]} {files[2]}\n' +
                                          '\n'.join(f'{name}:' for name in files[1:]) + '\n')
        (kernel / 'modules.builtin').write_text('kernel/lib/crypto/libchacha.ko\n')
        self.assertEqual(modules.closure(kernel), sorted(files))
        (kernel / files[2]).unlink()
        with self.assertRaisesRegex(ValueError, 'missing'): modules.closure(kernel)
        (kernel / files[2]).touch()
        (kernel / 'modules.dep').write_text(f'{files[0]}: ../escape.ko\n')
        with self.assertRaisesRegex(ValueError, 'Unsafe'): modules.closure(kernel)

    def test_builtin_and_missing_wireguard(self):
        (self.root / 'modules.dep').write_text('')
        (self.root / 'modules.builtin').write_text('kernel/drivers/net/wireguard/wireguard.ko\nkernel/net/netfilter/nf_tables.ko\n')
        self.assertEqual(modules.closure(self.root), [])
        (self.root / 'modules.builtin').write_text('kernel/net/netfilter/nf_tables.ko\n')
        with self.assertRaisesRegex(ValueError, 'no wireguard'): modules.closure(self.root)

    def test_guest_installer_stages_binary_helper_and_disabled_unit(self):
        source = self.root / 'source'; source.mkdir()
        buildroot = self.root / 'buildroot'; buildroot.mkdir()
        destination = self.root / 'image'; destination.mkdir()
        sdk = buildroot / 'opt/intel/sgxsdk'; sdk.mkdir(parents=True)
        (sdk / 'environment').write_text(':\n')
        cocoon = source / 'cocoon'; cocoon.mkdir()
        (cocoon / 'CMakeLists.txt').touch()
        compiled = cocoon / 'build-reprodebian'; compiled.mkdir()
        names = ['tee/cocoon/tdx/sgx-enclave/seal-client', 'tee/cocoon/tdx/sgx-enclave/seal-server',
                 'tee/gen-cert', 'tee/router', 'worker-runner', 'client-runner', 'proxy-runner', 'key-manager-runner',
                 'sync-time', 'tee/cocoon-subst', 'tee/cocoon-wireguard', 'tee/health-monitor', 'tee/health-client',
                 'tee/sev-info', 'tee/cocoon/tdx/sgx-enclave/enclave.signed.so', 'tee/cocoon/tdx/sgx-enclave/mr_enclave.txt']
        for name in names:
            path = compiled / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture\n'); path.chmod(0o755)
        shutil.copy2(BINARY, compiled / 'tee/cocoon-wireguard')
        shutil.copytree(ROOT / 'reprodebian/cocoon-init', source / 'cocoon-init')
        template = cocoon / 'scripts/wireguard/systemd'; template.mkdir(parents=True)
        shutil.copy2(ROOT / 'scripts/wireguard/systemd/cocoon-wireguard.service', template)
        (source / 'pkg-cache').mkdir(); (source / 'pkg-aux').mkdir()
        (source / 'pkg-aux/fuse-archive-blockdev.patch').touch()
        fakebin = self.root / 'fakebin'; fakebin.mkdir()
        # External build/archive tools are mocked; the installation script and installed binary are real.
        for name in ('mkosi-chroot', 'tar', 'patch'):
            path = fakebin / name; path.write_text('#!/bin/sh\nexit 0\n'); path.chmod(0o755)
        environment = dict(os.environ, SRCDIR=str(source), BUILDROOT=str(buildroot), DESTDIR=str(destination),
                           PATH=str(fakebin) + ':' + os.environ['PATH'])
        stage = REAL_RUN(['bash', str(ROOT / 'reprodebian/mkosi.build')], env=environment,
                         capture_output=True, text=True, timeout=30)
        self.assertEqual(stage.returncode, 0, stage.stderr)
        installed = destination / 'usr/bin/cocoon-wireguard'
        result = REAL_RUN([str(installed), '--help'], check=True, capture_output=True, text=True)
        self.assertIn('cocoon-wireguard run', result.stdout)
        helper = destination / 'usr/bin/cocoon-wireguard-prepare'
        self.assertTrue(os.access(helper, os.X_OK))
        unit = destination / 'lib/systemd/system/cocoon-wireguard.service'
        self.assertEqual(unit.read_text(), (ROOT / 'scripts/wireguard/systemd/cocoon-wireguard.service').read_text())
        self.assertFalse((destination / 'etc/systemd/system/multi-user.target.wants/cocoon-wireguard.service').exists())


if __name__ == '__main__':
    unittest.main()
