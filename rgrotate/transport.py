"""Bounded, read-only probes using our audited Unlicense spd_dump backend."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time
import xml.etree.ElementTree as ET


class ProbeError(RuntimeError):
    pass


def loader_entries(pac):
    """Take loader code and addresses from the same model-specific PAC."""
    if pac.product != 'ums512_1h10':
        raise ProbeError(f'Unsupported product: {pac.product!r}')
    root = ET.fromstring(pac.xml_text)
    result = []
    for name, expected in [('FDL', 0x5500), ('FDL2', 0x9EFFFE00)]:
        entries = pac.entries_for_id(name)
        nodes = [n for n in root.iter('File') if n.findtext('ID') == name]
        if len(entries) != 1 or len(nodes) != 1:
            raise ProbeError(f'Exactly one {name} image and XML entry are required')
        address = int(nodes[0].findtext('Block/Base', default='-1'), 0)
        if address != expected:
            raise ProbeError(f'Unrecognized {name} address: {address:#x}')
        if not 0 < entries[0].size <= 16 * 1024 * 1024:
            raise ProbeError(f'Unreasonable {name} size')
        result.append((entries[0], address))
    return result


def probe_arguments(pac, out_dir, backend, wait=30):
    if not isinstance(wait, int) or not 1 <= wait <= 30:
        raise ProbeError('wait must be between 1 and 30 seconds')
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    args = [str(Path(backend).resolve()), '--read-only', '--wait', str(wait),
            'timeout', '15000']
    for n, (entry, address) in enumerate(loader_entries(pac), 1):
        target = out / f'fdl{n}.bin'
        pac.extract(entry, target)
        target.chmod(0o600)
        args += ['fdl', str(target), hex(address)]
    args += ['disable_transcode', 'partition_list', str(out / 'partitions.xml'),
             'read_part', 'boot_a', '0', '1048576', str(out / 'boot_a-first-1MiB.bin'),
             'power_off']
    return args


def run_bounded(args, out_dir, total_timeout=150, idle_timeout=45):
    """No shell expansion, retries, stdin confirmations, or unbounded USB waits."""
    out = Path(out_dir)
    started = last_io = time.monotonic()
    p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, bufsize=0)
    selector = selectors.DefaultSelector()
    selector.register(p.stdout, selectors.EVENT_READ)
    written = 0
    try:
        with (out / 'probe.log').open('wb') as log:
            while selector.get_map():
                now = time.monotonic()
                if now - started > total_timeout or now - last_io > idle_timeout:
                    raise ProbeError('USB probe timed out; reconnect the device before retrying')
                for key, _ in selector.select(1):
                    data = key.fileobj.read(65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    last_io = time.monotonic()
                    if written + len(data) > 4 * 1024 * 1024:
                        raise ProbeError('Unexpectedly large USB log')
                    log.write(data)
                    log.flush()
                    written += len(data)
                    print(data.decode(errors='replace'), end='', flush=True)
            rc = p.wait(timeout=5)
            if rc:
                raise ProbeError(f'USB backend exited {rc}; see {out / "probe.log"}')
    except BaseException:
        if p.poll() is None:
            p.kill()
        p.wait(timeout=5)
        raise
    finally:
        selector.close()


def probe(pac, out_dir, backend, wait=30):
    out = Path(out_dir).resolve()
    state = {'status': 'running', 'writes_to_device_storage': False,
             'ram_loader_execution': True, 'product': pac.product}
    args = probe_arguments(pac, out, backend, wait)
    try:
        run_bounded(args, out)
        table = out / 'partitions.xml'
        if not table.is_file() or table.stat().st_size > 1024 * 1024:
            raise ProbeError('Missing or unreasonable partition table')
        parsed = ET.fromstring(table.read_bytes())
        names = {n.get('id') or n.get('name') for n in parsed.iter()}
        if not {'super', 'boot_a', 'userdata'}.issubset(names):
            raise ProbeError('Partition table does not describe the expected layout')
        sample = out / 'boot_a-first-1MiB.bin'
        if sample.stat().st_size != 1048576:
            raise ProbeError('Incomplete boot partition sample')
        state.update(status='read_completed', sample_sha256=hashlib.sha256(sample.read_bytes()).hexdigest(),
                     sample_bytes=sample.stat().st_size,
                     device_identity_verified=False,
                     limitation='Compare the sample hash and complete partition layout with a trusted baseline before any write.')
        return state
    except Exception as exc:
        state.update(status='failed', error=str(exc))
        raise
    finally:
        (out / 'probe-result.json').write_text(json.dumps(state, indent=2) + '\n')
