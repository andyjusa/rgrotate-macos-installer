"""Guarded Full installation on an already compatible GammaOS RG Rotate.

This is not a replay of the vendor's repartition/bootloader/NV operations.
Every storage write is followed by a complete readback before the next write.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import time

from .target import (InstallError, REQUIRED_BEFORE_READS, patch_misc,
                     sha256_file, validate_pac, validate_preflight)
from .transport import loader_entries

MIB = 1024 * 1024
BEFORE_SIZES = dict(REQUIRED_BEFORE_READS)
WRITE_ORDER = ('super', 'vbmeta_system_a', 'vbmeta_system_ext_a',
               'vbmeta_vendor_a', 'vbmeta_product_a', 'misc')
WRITE_PROMPT = b'Answer "yes" to confirm the "write partition" command: '


def save_json(path, value):
    path = Path(path)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    tmp.replace(path)


def verify_file(path, size, digest):
    path = Path(path)
    if not path.is_file() or path.stat().st_size != size:
        raise InstallError(f'Incomplete file: {path.name}')
    actual = sha256_file(path)
    if actual != digest:
        raise InstallError(f'SHA-256 mismatch: {path.name}')
    return {'bytes': size, 'sha256': actual}


class InstallSession:
    """Strict ordering for one backend connection, with no retry or restore."""
    def __init__(self, pac, out, images):
        self.pac, self.out, self.images = pac, Path(out), images
        self.preflight_ok = False
        self.confirmed = 0
        self.verified = 0
        self.state = {
            'status': 'prepared', 'writes_started': False,
            'verified_partitions': {}, 'restore_user_data': False,
            'factory_reset_requested': False, 'boot_verified': False,
            'scope': 'Full OS over FDL, preserve layout and boot chain, Recovery wipe',
        }
        self.save()

    def save(self):
        save_json(self.out / 'install-result.json', self.state)

    def checkpoint(self, token):
        if token == 'preflight':
            if self.preflight_ok or self.confirmed:
                raise InstallError('Duplicate or late preflight checkpoint')
            self.state['preflight'] = validate_preflight(self.out, self.pac)
            before = (self.out / 'before/misc.bin').read_bytes()
            patched = patch_misc(before)
            target = self.out / 'images/misc.bin'
            with target.open('xb') as stream:
                stream.write(patched)
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(0o600)
            self.images['misc'] = {'size': len(patched), 'sha256': sha256_file(target)}
            self.preflight_ok = True
            self.state['status'] = 'preflight_verified'
        else:
            if not self.preflight_ok or self.verified >= len(WRITE_ORDER):
                raise InstallError('Unexpected verification checkpoint')
            part = WRITE_ORDER[self.verified]
            if token != 'verified_' + part or self.confirmed != self.verified + 1:
                raise InstallError(f'Out-of-order checkpoint: {token}')
            image = self.images[part]
            checked = verify_file(self.out / f'after/{part}.bin', image['size'], image['sha256'])
            if part == 'misc':
                original = (self.out / 'before/misc.bin').read_bytes()
                actual = (self.out / 'after/misc.bin').read_bytes()
                if actual != patch_misc(original):
                    raise InstallError('misc readback changed unrelated fields')
                self.state['factory_reset_requested'] = True
            self.state['verified_partitions'][part] = checked
            self.verified += 1
            self.state['status'] = 'verified_' + part
        self.save()
        return ('continue ' + token + '\n').encode('ascii')

    def confirm_write(self):
        if not self.preflight_ok or self.confirmed != self.verified or self.confirmed >= len(WRITE_ORDER):
            raise InstallError('Unexpected write prompt; no confirmation sent')
        part = WRITE_ORDER[self.confirmed]
        spec = self.images[part]
        # Recheck the exact local source at each write boundary.
        verify_file(self.out / f'images/{part}.bin', spec['size'], spec['sha256'])
        self.state.update(status='writing_' + part, writes_started=True,
                          current_partition=part)
        self.save()
        self.confirmed += 1
        return b'yes\n'

    def completed(self):
        if self.confirmed != len(WRITE_ORDER) or self.verified != len(WRITE_ORDER):
            raise InstallError('Backend exited before all writes were verified')
        self.state['status'] = 'storage_verified_awaiting_recovery_boot'
        self.state['power_off_acknowledged'] = True
        self.save()


def prepare_install(pac, out_dir, backend, wait=30):
    if not isinstance(wait, int) or not 1 <= wait <= 30:
        raise InstallError('wait must be between 1 and 30 seconds')
    backend = Path(backend).resolve(strict=True)
    if not backend.is_file() or not os.access(backend, os.X_OK):
        raise InstallError('Backend must be an executable regular file')
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    for name in ('before', 'after', 'images'):
        (out / name).mkdir(mode=0o700)
    print('Checking pinned Full PAC and preparing local images...', flush=True)
    images = validate_pac(pac)
    needed = 2 * sum(item['size'] for item in images.values()) + sum(BEFORE_SIZES.values()) + 2*1024**3
    if shutil.disk_usage(out).free < needed:
        raise InstallError('Insufficient free disk space for images and complete readback')
    args = [str(backend), '--wait', str(wait), 'timeout', '15000']
    for n, (entry, address) in enumerate(loader_entries(pac), 1):
        target = out / f'fdl{n}.bin'
        pac.extract(entry, target)
        target.chmod(0o600)
        args += ['fdl', str(target), hex(address)]
    for part, spec in images.items():
        target = out / f'images/{part}.bin'
        pac.extract(spec['entry'], target)
        target.chmod(0o600)
        verify_file(target, spec['size'], spec['sha256'])
        print(f'Prepared {part}: {spec["size"]} bytes', flush=True)
    args += ['disable_transcode', 'blk_size', '32768',
             'partition_list', str(out / 'partitions.xml')]
    for part, size in BEFORE_SIZES.items():
        args += ['read_part', part, '0', str(size), str(out / f'before/{part}.bin')]
    # Exercise an actual >4 GiB named read before attempting the 64-bit write.
    args += ['read_part', 'super', str(images['super']['size'] - MIB), str(MIB),
             str(out / 'before/super-tail.bin')]
    args += ['checkpoint', 'preflight']
    for part in WRITE_ORDER:
        size = MIB if part == 'misc' else images[part]['size']
        # Keep the original 4 KiB write size. Larger reads are tested by preflight.
        args += ['blk_size', '4096', 'write_part', part, str(out / f'images/{part}.bin'),
                 'blk_size', '32768', 'read_part', part, '0', str(size), str(out / f'after/{part}.bin'),
                 'checkpoint', 'verified_' + part]
    args += ['power_off']
    return args, InstallSession(pac, out, images)


def run_session(args, session, total_timeout=7200, idle_timeout=180):
    """Bound USB waits and only answer exact prompts at verified boundaries."""
    started = last_io = time.monotonic()
    log = (session.out / 'install.log').open('xb')
    try:
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, bufsize=0)
    except BaseException as exc:
        log.close()
        session.state.update(status='failed', error=str(exc), automatic_retry=False)
        session.save()
        raise
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    pending = bytearray()
    written = 0
    try:
        with log:
            while selector.get_map():
                now = time.monotonic()
                if now-started > total_timeout or now-last_io > idle_timeout:
                    raise InstallError('Installation timeout; no automatic retry or reset')
                for key, _ in selector.select(1):
                    data = key.fileobj.read(65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    last_io = time.monotonic()
                    written += len(data)
                    if written > 8*1024*1024:
                        raise InstallError('Unexpectedly large backend log')
                    log.write(data)
                    log.flush()
                    print(data.decode(errors='replace'), end='', flush=True)
                    pending.extend(data)
                    while b'\n' in pending:
                        line, _, remainder = pending.partition(b'\n')
                        pending = bytearray(remainder)
                        if line.startswith(b'CHECKPOINT '):
                            try:
                                token = line[len(b'CHECKPOINT '):].decode('ascii')
                            except UnicodeDecodeError as exc:
                                raise InstallError('Invalid checkpoint encoding') from exc
                            answer = session.checkpoint(token)
                            process.stdin.write(answer)
                            process.stdin.flush()
                            last_io = time.monotonic()
                        elif line.startswith(b'PROGRESS '):
                            save_json(session.out / 'progress.json', {
                                'line': line.decode('ascii', errors='strict'),
                                'elapsed_seconds': round(time.monotonic()-started, 1),
                                'stage': session.state['status'],
                            })
                    if pending == WRITE_PROMPT:
                        answer = session.confirm_write()
                        process.stdin.write(answer)
                        process.stdin.flush()
                        pending.clear()
                        last_io = time.monotonic()
                    elif len(pending) > 65536:
                        raise InstallError('Oversized unterminated backend output')
            rc = process.wait(timeout=5)
            if rc:
                raise InstallError(f'USB backend exited {rc}; inspect install.log before reconnecting')
            if pending:
                raise InstallError('Incomplete backend output at exit')
            session.completed()
    except BaseException as exc:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        session.state.update(status='failed', error=str(exc), automatic_retry=False)
        session.save()
        raise
    finally:
        selector.close()
        process.stdin.close()
        process.stdout.close()
    return session.state


def install(pac, out_dir, backend, wait=30):
    old_umask = os.umask(0o077)
    try:
        args, session = prepare_install(pac, out_dir, backend, wait)
        print('Ready: waiting up to 30 seconds for powered-off RG Rotate with Back held and USB connected.', flush=True)
        return run_session(args, session)
    finally:
        os.umask(old_umask)
