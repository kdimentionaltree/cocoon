#!/usr/bin/env python3
"""Bounded two-worker PyTorch Gloo/NCCL smoke test in the guest host network namespace."""

import argparse
from datetime import timedelta
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time


def require(condition, message):
    if not condition:
        raise ValueError(message)


def layout(config):
    require(config['format'] == 'cocoon-wireguard-config-v1', 'Unsupported configuration')
    interface = config['interface']
    require(re.fullmatch(r'wg[A-Za-z0-9_-]*', interface) and len(interface) <= 15, 'Invalid overlay interface')
    require(len(config['peers']) == 1 and config['peers'][0]['required'] is True,
            'Collective smoke test requires exactly two mutually required workers')
    nodes = [config, config['peers'][0]]
    require(all(type(node['node_rank']) is int for node in nodes) and
            {node['node_rank'] for node in nodes} == {0, 1}, 'Expected integer ranks 0 and 1')
    addresses = [str(ipaddress.IPv4Address(node['overlay_ipv4'])) for node in nodes]
    require(addresses[0] != addresses[1], 'Duplicate overlay addresses')
    require(type(config['node_rank']) is int, 'Invalid local rank')
    leader = next(node['overlay_ipv4'] for node in nodes if node['node_rank'] == 0)
    return config['node_rank'], interface, leader


def transport_environment(interface):
    return {'NCCL_NET': 'Socket', 'NCCL_IB_DISABLE': '1', 'NCCL_SOCKET_IFNAME': '=' + interface,
            'NCCL_SOCKET_FAMILY': 'AF_INET', 'NCCL_OOB_NET_ENABLE': '0', 'GLOO_SOCKET_IFNAME': interface,
            'NCCL_DEBUG': 'INFO', 'NCCL_DEBUG_SUBSYS': 'INIT,NET'}


def make_store(dist, config, leader, port, timeout):
    if config['node_rank'] != 0:
        return dist.TCPStore(leader, port, 2, False, timedelta(seconds=timeout), use_libuv=False)
    # TCPStore also connects locally to its own listener. Bind its exact overlay address;
    # SO_BINDTODEVICE would exclude that loopback connection. The readiness gate admits
    # local self traffic only while the group is ready and still rejects underlay ingress.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((config['overlay_ipv4'], port))
        sock.listen(2)
        fd = sock.detach()
    finally:
        sock.close()
    try:
        return dist.TCPStore(leader, port, 2, True, timedelta(seconds=timeout),
                             master_listen_fd=fd, use_libuv=False)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def worker(args, config):
    rank, interface, leader = layout(config)
    os.environ.update(transport_environment(interface))
    try:
        import torch
        import torch.distributed as dist
    except ImportError as error:
        raise ValueError('Run collective.py in the chosen inference image with PyTorch installed') from error
    require(dist.is_available(), 'PyTorch distributed support unavailable')
    require(dist.is_gloo_available() if args.backend == 'gloo' else dist.is_nccl_available(), 'Backend unavailable')
    if args.backend == 'nccl':
        require(torch.cuda.is_available() and args.device < torch.cuda.device_count(), 'Requested GPU unavailable')
        torch.cuda.set_device(args.device)
        device = torch.device('cuda', args.device)
    else:
        device = torch.device('cpu')
    store = make_store(dist, config, leader, args.port, args.seconds)
    initialized = False
    samples = []
    try:
        dist.init_process_group(backend=args.backend, store=store, rank=rank, world_size=2,
                                timeout=timedelta(seconds=args.seconds))
        initialized = True
        for size in args.elements:
            for iteration in range(args.iterations):
                tensor = torch.full((size,), rank + 1, dtype=torch.float32, device=device)
                if args.backend == 'nccl':
                    torch.cuda.synchronize(args.device)
                start = time.monotonic()
                dist.all_reduce(tensor, op=dist.ReduceOp.SUM)
                if args.backend == 'nccl':
                    torch.cuda.synchronize(args.device)
                elapsed = time.monotonic() - start
                require(bool(torch.all(tensor == 3).item()), 'Collective returned incorrect results')
                samples.append({'elements': size, 'iteration': iteration, 'milliseconds': round(elapsed * 1000, 3)})
        dist.barrier()
    finally:
        if initialized:
            dist.destroy_process_group()
    print(json.dumps({'format': 'cocoon-wireguard-collective-v1', 'backend': args.backend,
                      'attestation_type': config['attestation']['type'],
                      'torch_version': torch.__version__, 'rank': rank, 'interface': interface,
                      'master_ipv4': leader, 'samples': samples, 'result': 'passed'}, indent=2), flush=True)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('/run/spec/wireguard-config.json'))
    parser.add_argument('--backend', required=True, choices=['gloo', 'nccl'])
    parser.add_argument('--port', type=int, default=29500)
    parser.add_argument('--seconds', type=int, default=90, help='Hard deadline for the complete worker process')
    parser.add_argument('--device', type=int, default=0)
    parser.add_argument('--elements', default='1024,65536,1048576')
    parser.add_argument('--iterations', type=int, default=3)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(1024 <= args.port <= 65535 and args.port not in (51822, 51823, 8000), 'Invalid/reserved rendezvous port')
    require(1 <= args.seconds <= 300 and 1 <= args.iterations <= 20 and 0 <= args.device <= 127, 'Invalid test bounds')
    args.elements = [int(value) for value in args.elements.split(',')]
    require(1 <= len(args.elements) <= 8 and all(1 <= value <= 16 * 1024 * 1024 for value in args.elements),
            'Invalid collective tensor sizes')
    return args


def main():
    args = parse_args()
    require(args.config.is_file() and not args.config.is_symlink() and args.config.stat().st_size <= 1024 * 1024,
            'Expected bounded regular configuration')
    config = json.loads(args.config.read_text())
    layout(config)
    require(args.port not in (config['listen_port'], config['admission_port']), 'Rendezvous conflicts with overlay listener')
    if args.worker:
        worker(args, config)
        return
    # The hard parent deadline also covers import, GPU initialization and backend shutdown hangs.
    child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], '--worker'],
                             start_new_session=True)
    try:
        require(child.wait(timeout=args.seconds) == 0, 'Collective worker failed')
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(f'WireGuard collective failed: {error}')
