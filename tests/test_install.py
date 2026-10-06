"""Tiny images and a Python subprocess exercise the runner without USB/PAC files."""
import contextlib
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from unittest.mock import patch

from rgrotate import install as installer
from rgrotate.target import InstallError


FAKE_BACKEND = r'''
import json
import os
from pathlib import Path
import sys
import time

out, mode = Path(sys.argv[1]), sys.argv[2]
parts = ('super', 'vbmeta_system_a', 'vbmeta_system_ext_a',
         'vbmeta_vendor_a', 'vbmeta_product_a', 'misc')
events = (out / 'backend-events.jsonl').open('x')
(out / 'backend.pid').write_text(str(os.getpid()))

def record(kind, value):
    events.write(json.dumps({'kind': kind, 'value': value}) + '\n')
    events.flush()

def emit(value):
    data = value.encode('ascii')
    if mode == 'split_success':
        for pos in range(0, len(data), 3):
            os.write(1, data[pos:pos+3])
            time.sleep(0.001)
    else:
        os.write(1, data)

def answer():
    value = sys.stdin.readline()
    record('answer', value)
    if not value:
        sys.exit(33)
    return value

def checkpoint(token):
    record('checkpoint', token)
    emit('CHECKPOINT ' + token + '\n')
    if answer() != 'continue ' + token + '\n':
        sys.exit(34)

def prompt():
    record('prompt', 'write')
    emit('Answer "yes" to confirm the "write partition" command: ')
    if answer() != 'yes\n':
        sys.exit(35)
    emit('\n')

if mode in ('idle_timeout', 'total_timeout'):
    emit('BACKEND_READY\n')
    while True:
        if mode == 'total_timeout':
            emit('still reading\n')
        time.sleep(0.01)
if mode == 'premature_prompt':
    prompt()
    sys.exit(36)

checkpoint('preflight')
if mode == 'premature_exit':
    sys.exit(0)
if mode == 'source_mutation':
    target = out / 'images/super.bin'
    original = target.read_bytes()
    target.write_bytes(b'!' + original[1:])

for part in parts:
    prompt()
    if mode == 'double_prompt' and part == 'super':
        prompt()
        sys.exit(37)
    data = (out / ('images/' + part + '.bin')).read_bytes()
    if part == 'super' and mode == 'bad_readback':
        data = b'!' + data[1:]
    if part == 'super' and mode == 'short_readback':
        data = data[:-1]
    (out / ('after/' + part + '.bin')).write_bytes(data)
    emit('PROGRESS read ' + part + ' ' + str(len(data)) + ' ' + str(len(data)) + '\n')
    if mode == 'out_of_order_checkpoint' and part == 'super':
        checkpoint('verified_vbmeta_vendor_a')
        sys.exit(38)
    checkpoint('verified_' + part)

record('power_off', 'ack')
emit('POWER_OFF_ACK\n')
sys.exit(7 if mode == 'nonzero_after_verification' else 0)
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def patch_tiny_misc(original):
    return b'WIPE!!' + original[6:]


class TinyPac:
    def __init__(self, images):
        self.images = images

    def extract(self, entry, destination):
        pathlib.Path(destination).write_bytes(self.images[entry])


class InstallRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.out = self.root / 'run'
        self.out.mkdir()
        for name in ('images', 'before', 'after'):
            (self.out / name).mkdir()
        (self.out / 'before/misc.bin').write_bytes(b'M' * 64)
        images = {}
        for part in installer.WRITE_ORDER:
            if part == 'misc':
                continue
            data = (part.encode('ascii') + b'_' * 64)[:64]
            (self.out / f'images/{part}.bin').write_bytes(data)
            images[part] = {'size': len(data), 'sha256': digest(data)}
        self.session = installer.InstallSession(object(), self.out, images)
        self.backend = self.root / 'fake_backend.py'
        self.backend.write_text(textwrap.dedent(FAKE_BACKEND), encoding='utf-8')
        self.preflight = patch.object(installer, 'validate_preflight', return_value={'identity_verified': True}).start()
        self.addCleanup(patch.stopall)
        patch.object(installer, 'patch_misc', side_effect=patch_tiny_misc).start()

    def run_backend(self, mode='success', **timeouts):
        args = [sys.executable, '-u', str(self.backend), str(self.out), mode]
        with contextlib.redirect_stdout(io.StringIO()):
            return installer.run_session(args, self.session, **timeouts)

    def events(self):
        path = self.out / 'backend-events.jsonl'
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def answers(self):
        return [event['value'] for event in self.events() if event['kind'] == 'answer']

    def saved_state(self):
        return json.loads((self.out / 'install-result.json').read_text())

    def assert_failed(self, writes_started):
        state = self.saved_state()
        self.assertEqual(state['status'], 'failed')
        self.assertEqual(state['writes_started'], writes_started)
        self.assertFalse(state['automatic_retry'])
        self.assertFalse(state.get('power_off_acknowledged', False))
        self.assertFalse(state['boot_verified'])

    def assert_complete_flow(self, mode):
        state = self.run_backend(mode)
        expected = ['continue preflight\n']
        for part in installer.WRITE_ORDER:
            expected += ['yes\n', f'continue verified_{part}\n']
        self.assertEqual(self.answers(), expected)
        self.assertEqual(state, self.saved_state())
        self.assertEqual(state['status'], 'storage_verified_awaiting_recovery_boot')
        self.assertEqual(list(state['verified_partitions']), list(installer.WRITE_ORDER))
        self.assertEqual((self.session.confirmed, self.session.verified), (6, 6))
        self.assertTrue(state['power_off_acknowledged'])
        self.assertTrue(state['factory_reset_requested'])
        self.assertFalse(state['restore_user_data'])
        self.assertFalse(state['boot_verified'])
        self.assertEqual(self.events()[-1], {'kind': 'power_off', 'value': 'ack'})
        self.assertEqual((self.out / 'images/misc.bin').read_bytes(), patch_tiny_misc(b'M' * 64))
        progress = json.loads((self.out / 'progress.json').read_text())
        self.assertEqual(progress['line'], 'PROGRESS read misc 64 64')
        self.assertIn(b'CHECKPOINT verified_misc\n', (self.out / 'install.log').read_bytes())

    def test_complete_six_write_flow_and_power_off_state(self):
        self.assert_complete_flow('success')

    def test_split_prompt_and_checkpoint_stream(self):
        self.assert_complete_flow('split_success')

    def test_preflight_failure_sends_no_continue_or_yes(self):
        self.preflight.side_effect = InstallError('wrong target identity')
        with self.assertRaisesRegex(InstallError, 'wrong target identity'):
            self.run_backend()
        self.assertEqual(self.answers(), [])
        self.assert_failed(False)

    def test_readback_hash_failure_prevents_next_write(self):
        with self.assertRaisesRegex(InstallError, 'SHA-256 mismatch'):
            self.run_backend('bad_readback')
        self.assertEqual(self.answers(), ['continue preflight\n', 'yes\n'])
        self.assertEqual((self.session.confirmed, self.session.verified), (1, 0))
        self.assert_failed(True)

    def test_short_readback_prevents_next_write(self):
        with self.assertRaisesRegex(InstallError, 'Incomplete file'):
            self.run_backend('short_readback')
        self.assertEqual(self.answers(), ['continue preflight\n', 'yes\n'])
        self.assert_failed(True)

    def test_source_hash_is_rechecked_before_first_yes(self):
        with self.assertRaisesRegex(InstallError, 'SHA-256 mismatch'):
            self.run_backend('source_mutation')
        self.assertEqual(self.answers(), ['continue preflight\n'])
        self.assert_failed(False)

    def test_prompt_before_preflight_is_refused(self):
        with self.assertRaisesRegex(InstallError, 'Unexpected write prompt'):
            self.run_backend('premature_prompt')
        self.assertEqual(self.answers(), [])
        self.assert_failed(False)

    def test_second_prompt_without_readback_is_refused(self):
        with self.assertRaisesRegex(InstallError, 'Unexpected write prompt'):
            self.run_backend('double_prompt')
        self.assertEqual(self.answers(), ['continue preflight\n', 'yes\n'])
        self.assert_failed(True)

    def test_out_of_order_checkpoint_is_refused(self):
        with self.assertRaisesRegex(InstallError, 'Out-of-order checkpoint'):
            self.run_backend('out_of_order_checkpoint')
        self.assertEqual(self.answers(), ['continue preflight\n', 'yes\n'])
        self.assert_failed(True)

    def test_nonzero_exit_after_all_verifications_is_failure(self):
        with self.assertRaisesRegex(InstallError, 'exited 7'):
            self.run_backend('nonzero_after_verification')
        self.assertEqual((self.session.confirmed, self.session.verified), (6, 6))
        self.assert_failed(True)

    def test_zero_exit_before_writes_is_not_success(self):
        with self.assertRaisesRegex(InstallError, 'before all writes were verified'):
            self.run_backend('premature_exit')
        self.assert_failed(False)

    def test_idle_timeout_kills_backend(self):
        real_popen, processes = subprocess.Popen, []

        def spawn(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process

        with patch.object(installer.subprocess, 'Popen', side_effect=spawn):
            with self.assertRaisesRegex(InstallError, 'timeout'):
                self.run_backend('idle_timeout', total_timeout=5, idle_timeout=0.05)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())
        self.assertLess(processes[0].returncode, 0)
        self.assertEqual(self.answers(), [])
        self.assert_failed(False)

    def test_total_timeout_is_enforced_despite_output(self):
        with self.assertRaisesRegex(InstallError, 'timeout'):
            self.run_backend('total_timeout', total_timeout=0.08, idle_timeout=5)
        self.assert_failed(False)

    def test_existing_log_is_preserved_without_launching_backend(self):
        original = b'previous evidence\x00\xff'
        (self.out / 'install.log').write_bytes(original)
        with patch.object(installer.subprocess, 'Popen') as popen:
            with self.assertRaises(FileExistsError):
                self.run_backend()
            popen.assert_not_called()
        self.assertEqual((self.out / 'install.log').read_bytes(), original)

    def test_existing_misc_image_is_never_overwritten(self):
        original = b'existing misc evidence'
        (self.out / 'images/misc.bin').write_bytes(original)
        with self.assertRaises(FileExistsError):
            self.run_backend()
        self.assertEqual((self.out / 'images/misc.bin').read_bytes(), original)
        self.assertEqual(self.answers(), [])
        self.assert_failed(False)


class PrepareInstallTests(unittest.TestCase):
    def test_existing_output_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            sentinel = out / 'evidence.bin'
            sentinel.write_bytes(b'keep')
            with patch.object(installer, 'validate_pac') as validate:
                with self.assertRaises(FileExistsError):
                    installer.prepare_install(object(), out, sys.executable)
                validate.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b'keep')

    def test_plan_uses_six_guarded_writes_and_finishes_with_power_off(self):
        data = {part: (part.encode() + b'_' * 64)[:64]
                for part in installer.WRITE_ORDER if part != 'misc'}
        data.update(fdl1=b'loader1', fdl2=b'loader2')
        pac = TinyPac(data)
        images = {part: {'entry': part, 'size': len(value), 'sha256': digest(value)}
                  for part, value in data.items() if not part.startswith('fdl')}
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(patch.object(installer, 'validate_pac', return_value=images))
            stack.enter_context(patch.object(installer, 'loader_entries', return_value=[('fdl1', 0x5500), ('fdl2', 0x9efffe00)]))
            stack.enter_context(patch.object(installer, 'BEFORE_SIZES', {'misc': 64, 'boot_a': 64}))
            stack.enter_context(patch.object(installer, 'MIB', 64))
            stack.enter_context(patch.object(installer.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=20*1024**3)))
            args, session = installer.prepare_install(pac, pathlib.Path(tmp) / 'new', sys.executable)
            writes = [args[i+1] for i, arg in enumerate(args) if arg == 'write_part']
            checkpoints = [args[i+1] for i, arg in enumerate(args) if arg == 'checkpoint']
            self.assertEqual(writes, list(installer.WRITE_ORDER))
            self.assertEqual(checkpoints, ['preflight'] + ['verified_' + part for part in installer.WRITE_ORDER])
            self.assertEqual(args[-1], 'power_off')
            self.assertNotIn('erase_part', args)
            self.assertNotIn('repartition', args)
            self.assertEqual(session.state['status'], 'prepared')
            self.assertFalse((session.out / 'images/misc.bin').exists())
            for part in writes:
                index = args.index('write_part', 0 if part == writes[0] else index + 1)
                self.assertEqual(args[index-2:index], ['blk_size', '4096'])


if __name__ == '__main__':
    unittest.main()
