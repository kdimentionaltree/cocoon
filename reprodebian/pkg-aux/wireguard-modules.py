#!/usr/bin/env python3
"""Resolve required modules from the installed guest kernel, before and after pruning."""

from pathlib import Path
import sys


# iptables-nft uses the compatibility layer for our ownership comment match.
# Those modules are loaded on demand and are not dependencies of nf_tables.
REQUIRED_MODULES = ('wireguard', 'nf_tables', 'nft_compat', 'xt_comment')


def module_name(path):
    return Path(path).name.split('.ko', 1)[0].replace('-', '_')


def closure(directory):
    directory = Path(directory)
    root = directory.resolve()
    dependencies = {}
    by_name = {}

    def safe(path):
        parts = Path(path).parts
        if not path or Path(path).is_absolute() or '..' in parts:
            raise ValueError(f'Unsafe module path: {path!r}')
        return path

    for line in (directory / 'modules.dep').read_text().splitlines():
        path, separator, rest = line.partition(':')
        if not separator:
            raise ValueError('Malformed modules.dep')
        safe(path)
        name = module_name(path)
        if path in dependencies or name in by_name:
            raise ValueError(f'Duplicate module: {path}')
        by_name[name] = path
        dependencies[path] = [safe(item) for item in rest.split()]
    builtins = {module_name(safe(path)) for path in (directory / 'modules.builtin').read_text().splitlines()}
    selected = set()
    pending = set()

    def visit(path):
        if path in pending:
            raise ValueError(f'Cyclic module dependency: {path}')
        if path in selected:
            return
        if path not in dependencies:
            raise ValueError(f'Module missing from dependency inventory: {path}')
        file = directory / path
        if not file.is_file() or not file.resolve().is_relative_to(root):
            raise ValueError(f'Module file missing or outside kernel directory: {path}')
        pending.add(path)
        for dependency in dependencies[path]:
            visit(dependency)
        pending.remove(path)
        selected.add(path)

    for name in REQUIRED_MODULES:
        if name in by_name:
            visit(by_name[name])
        elif name not in builtins:
            raise ValueError(f'Guest kernel has no {name} support')
    return sorted(selected)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('Usage: wireguard-modules.py GUEST_KERNEL_MODULE_DIRECTORY')
    try:
        for path in closure(sys.argv[1]):
            print('./' + path)
    except (OSError, ValueError) as error:
        sys.exit(f'WireGuard kernel dependency validation failed: {error}')
