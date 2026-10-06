"""Offline failure-path tests. No firmware images, device IDs, or USB calls."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zlib

from rgrotate import target


def good_misc():
    data = bytearray(target.MIB)
    # Distinct nonzero regions must survive the two-field BCB patch.
    data[32:45] = b'legacy-status'
    data[1100:1106] = b'vendor'
    data[17000:17004] = b'wipe'
    data[800000:800004] = b'tail'
    data[2048:2080] = bytes.fromhex(
        '5f61000042434142010200009f008e000000000000000000000000008532b0a3')
    struct.pack_into('<BIBB', data, 32768, 2, 0x56740ab0, 0, 0)
    return data


def update_control(data, offset, value):
    data[2048 + offset] = value
    struct.pack_into('<I', data, 2076, zlib.crc32(data[2048:2076]))


def layout_xml(mapping=None):
    root = ET.Element('Partitions')
    for name, size in (mapping or target.EXPECTED_PARTITIONS).items():
        ET.SubElement(root, 'Partition', id=name,
                      size='0xffffffff' if name == 'userdata' else str(size))
    return ET.tostring(root)


class MiscTests(unittest.TestCase):
    def test_patch_preserves_all_other_bytes(self):
        original = bytes(good_misc())
        result = target.patch_misc(original)
        self.assertEqual(len(result), target.MIB)
        self.assertEqual(result[:32], b'boot-recovery'.ljust(32, b'\0'))
        self.assertEqual(result[64:832], b'recovery\n--wipe_data\n'.ljust(768, b'\0'))
        self.assertEqual(result[32:64], original[32:64])
        self.assertEqual(result[832:], original[832:])
        self.assertEqual(original, bytes(good_misc()))

    def test_successful_active_a(self):
        state = target._validate_misc(good_misc())
        self.assertEqual(state['active_slot'], 'a')
        self.assertEqual(state['snapshot_status'], 'none')

    def test_rejects_short_or_oversized_misc(self):
        for data in (b'', good_misc()[:-1], good_misc() + b'\0'):
            with self.subTest(size=len(data)), self.assertRaises(target.InstallError):
                target.patch_misc(data)

    def test_rejects_pending_bcb_or_stage(self):
        for position in (0, 832):
            data = good_misc()
            data[position] = 1
            with self.subTest(position=position), self.assertRaises(target.InstallError):
                target.patch_misc(data)

    def test_rejects_corrupt_crc(self):
        data = good_misc()
        data[2076] ^= 1
        with self.assertRaisesRegex(target.InstallError, 'CRC32'):
            target.patch_misc(data)

    def test_rejects_incompatible_boot_control(self):
        # Recompute CRC to test the semantic guards independently of corruption.
        cases = [(1, ord('b')), (4, 0), (8, 2), (9, 1), (9, 0x42),
                 (9, 0x82), (9, 0xc2), (10, 1),
                 (12, 0x1f), (12, 0x80), (13, 1), (14, 0x8f)]
        for offset, value in cases:
            data = good_misc()
            update_control(data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(target.InstallError):
                target.patch_misc(data)

    def test_rejects_every_nonzero_virtual_ab_status(self):
        for status in (1, 2, 3, 4, 5, 255):
            data = good_misc()
            data[32773] = status
            with self.subTest(status=status), self.assertRaisesRegex(target.InstallError, 'NONE'):
                target.patch_misc(data)

    def test_rejects_unknown_or_uninitialized_virtual_ab(self):
        for offset, value in ((32768, 1), (32769, 0), (32774, 2)):
            data = good_misc()
            data[offset] = value
            with self.subTest(offset=offset), self.assertRaises(target.InstallError):
                target.patch_misc(data)
        data = good_misc()
        data[32768:32832] = bytes(64)
        with self.assertRaisesRegex(target.InstallError, 'uninitialized'):
            target.patch_misc(data)


class LayoutTests(unittest.TestCase):
    def test_all_74_names_sizes_and_remainder_sentinel(self):
        self.assertEqual(len(target.EXPECTED_PARTITIONS), 74)
        self.assertEqual(target.EXPECTED_PARTITIONS['super'], 5600)
        self.assertEqual(target.EXPECTED_PARTITIONS['userdata'], 0xffffffff)
        self.assertEqual(target._validate_layout(layout_xml()), target.EXPECTED_PARTITIONS)

    def test_missing_extra_changed_duplicate_partition_rejected(self):
        missing = dict(target.EXPECTED_PARTITIONS)
        missing.pop('misc')
        extra = dict(target.EXPECTED_PARTITIONS, unknown=1)
        changed = dict(target.EXPECTED_PARTITIONS, super=4096)
        duplicate = layout_xml().replace(b'</Partitions>', b'<Partition id="misc" size="1"/></Partitions>')
        for data in [layout_xml(missing), layout_xml(extra), layout_xml(changed), duplicate]:
            with self.subTest(data=data[-100:]), self.assertRaises(target.InstallError):
                target._validate_layout(data)

    def test_malformed_or_nested_xml_rejected(self):
        for data in [b'<', b'<Other/>', b'<Partitions><Unknown/></Partitions>',
                     b'<!DOCTYPE Partitions [<!ENTITY x "x">]><Partitions/>',
                     b'<Partitions><Partition id="misc" size="1"><Child/></Partition></Partitions>']:
            with self.subTest(data=data), self.assertRaises(target.InstallError):
                target._validate_layout(data)

    def test_noninteger_or_negative_size_rejected(self):
        for size in ['1.0', '-1', 'garbage']:
            data = layout_xml().replace(b'id="misc" size="1"', f'id="misc" size="{size}"'.encode())
            with self.subTest(size=size), self.assertRaises(target.InstallError):
                target._validate_layout(data)


class FileTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)

    def test_full_hash_includes_tail(self):
        data = b'a' * (target.MIB + 31) + b'tail'
        path = self.directory / 'image'
        path.write_bytes(data)
        self.assertEqual(target.sha256_file(path), hashlib.sha256(data).hexdigest())

    def test_missing_directory_and_symlink_rejected(self):
        link = self.directory / 'link'
        link.symlink_to(self.directory)
        for path in (self.directory / 'missing', self.directory, link):
            with self.subTest(path=path.name), self.assertRaises(target.InstallError):
                target.sha256_file(path)

    def test_source_mutation_during_read_rejected(self):
        path = self.directory / 'image'
        path.write_bytes(b'original')
        with self.assertRaisesRegex(target.InstallError, 'changed'):
            with target._regular_file(path) as (stream, _):
                stream.read()
                path.write_bytes(b'different')

    def test_replaced_same_size_file_rejected(self):
        path = self.directory / 'image'
        path.write_bytes(b'original')
        replacement = self.directory / 'replacement'
        replacement.write_bytes(b'original')
        with self.assertRaisesRegex(target.InstallError, 'changed'):
            with target._regular_file(path):
                replacement.replace(path)


class FakePac:
    product = 'ums512_1h10'
    firmware = '1.4.1'
    version = 'BP_R2.0.1'

    def __init__(self, path, specs, payloads):
        self.path = path
        self.size = path.stat().st_size
        self.xml_root = ET.Element('BMAConfig')
        self.entries = []
        self.payloads = payloads
        for partition, spec in specs.items():
            entry = SimpleNamespace(id=spec.identifier, name=spec.filename,
                                    size=spec.size, flag=1, partition=partition)
            self.entries.append(entry)
            node = ET.SubElement(self.xml_root, 'File')
            ET.SubElement(node, 'ID').text = spec.identifier
            ET.SubElement(node, 'Block', id=partition)

    def entries_for_id(self, identifier):
        return tuple(e for e in self.entries if e.id == identifier)

    def iter_chunks(self, entry):
        yield self.payloads[entry.partition]

    def read_range(self, entry, offset, length):
        return self.payloads[entry.partition][offset:offset + length]


class ValidationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.out = Path(temp.name)
        before = self.out / 'before'
        before.mkdir()
        self.source = self.out / 'fixture.pac'
        self.source.write_bytes(b'fixture archive')
        self.payloads = {}
        self.install = {}
        self.baseline = {}
        for original, destination in ((target.INSTALL_IMAGES, self.install),
                                      (target.BASELINE_IMAGES, self.baseline)):
            for name, spec in original.items():
                payload = (name + ':payload').encode()
                self.payloads[name] = payload
                destination[name] = replace(spec, size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest())
        self.reads = {name: 16 for name in target.REQUIRED_BEFORE_READS}
        for name, spec in self.baseline.items():
            self.reads[name] = spec.size
        self.reads['misc'] = target.MIB
        for name, size in self.reads.items():
            data = good_misc() if name == 'misc' else self.payloads.get(name, bytes(size))
            self.reads[name] = len(data)
            (before / f'{name}.bin').write_bytes(data)
        (before / 'super-tail.bin').write_bytes(bytes(target.MIB))
        (self.out / 'partitions.xml').write_bytes(layout_xml())
        patches = {
            'PAC_SIZE': self.source.stat().st_size,
            'PAC_SHA256': hashlib.sha256(self.source.read_bytes()).hexdigest(),
            'INSTALL_IMAGES': self.install, 'BASELINE_IMAGES': self.baseline,
            'REQUIRED_BEFORE_READS': self.reads,
        }
        for name, value in patches.items():
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.pac = FakePac(self.source, {**self.install, **self.baseline}, self.payloads)

    def test_validated_images_and_serializable_preflight(self):
        images = target.validate_pac(self.pac)
        self.assertEqual(set(images), set(self.install))
        for name, image in images.items():
            self.assertEqual(image['sha256'], self.install[name].sha256)
            self.assertEqual(image['size'], self.install[name].size)
        with mock.patch.object(target, '_hash_file', wraps=target._hash_file) as hashing:
            result = target.validate_preflight(self.out, self.pac)
        self.assertFalse(any(call.args[0] == self.source for call in hashing.call_args_list))
        self.assertEqual(result['before']['super-tail']['size'], target.MIB)
        self.assertEqual(len(result['before']), len(self.reads) + 1)
        json.dumps(result)

    def test_preflight_requires_previously_validated_pac(self):
        with self.assertRaisesRegex(target.InstallError, 'validate_pac'):
            target.validate_preflight(self.out, self.pac)

    def test_wrong_archive_hash_or_product_rejected(self):
        with mock.patch.object(target, 'PAC_SHA256', '0' * 64):
            with self.assertRaisesRegex(target.InstallError, 'SHA-256'):
                target.validate_pac(self.pac)
        self.pac.product = 'different'
        with self.assertRaisesRegex(target.InstallError, 'Only the pinned'):
            target.validate_pac(self.pac)

    def test_changed_source_after_validation_rejected(self):
        target.validate_pac(self.pac)
        self.source.write_bytes(b'changed archive')
        with self.assertRaisesRegex(target.InstallError, 'changed'):
            target.validate_preflight(self.out, self.pac)

    def test_wrong_entry_content_rejected(self):
        self.payloads['super'] += b'changed'
        with self.assertRaisesRegex(target.InstallError, 'image SHA-256/length'):
            target.validate_pac(self.pac)

    def test_duplicate_entry_and_bad_mapping_rejected(self):
        self.pac.entries.append(self.pac.entries[0])
        with self.assertRaisesRegex(target.InstallError, 'exactly one'):
            target.validate_pac(self.pac)
        self.pac.entries.pop()
        self.pac.xml_root.find('File/Block').set('id', 'userdata')
        with self.assertRaisesRegex(target.InstallError, 'incorrect XML'):
            target.validate_pac(self.pac)

    def test_renamed_entry_rejected(self):
        self.pac.entries[0].name = 'userdata.img'
        with self.assertRaisesRegex(target.InstallError, 'metadata'):
            target.validate_pac(self.pac)

    def test_missing_nv_backup_rejected(self):
        target.validate_pac(self.pac)
        (self.out / 'before/prodnv.bin').unlink()
        with self.assertRaisesRegex(target.InstallError, 'prodnv'):
            target.validate_preflight(self.out, self.pac)

    def test_short_nv_backup_rejected(self):
        target.validate_pac(self.pac)
        (self.out / 'before/persist.bin').write_bytes(b'')
        with self.assertRaisesRegex(target.InstallError, 'length'):
            target.validate_preflight(self.out, self.pac)

    def test_existing_boot_mismatch_rejected(self):
        target.validate_pac(self.pac)
        path = self.out / 'before/boot_a.bin'
        path.write_bytes(b'x' * self.reads['boot_a'])
        with self.assertRaisesRegex(target.InstallError, 'boot_a.*differs'):
            target.validate_preflight(self.out, self.pac)

    def test_missing_or_short_super_tail_rejected(self):
        target.validate_pac(self.pac)
        path = self.out / 'before/super-tail.bin'
        path.unlink()
        with self.assertRaisesRegex(target.InstallError, 'super-tail'):
            target.validate_preflight(self.out, self.pac)
        path.write_bytes(b'tail')
        with self.assertRaisesRegex(target.InstallError, 'length'):
            target.validate_preflight(self.out, self.pac)


if __name__ == '__main__':
    unittest.main()
