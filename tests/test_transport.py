import pathlib
import tempfile
import types
import unittest
from unittest.mock import patch

from rgrotate.transport import ProbeError, loader_entries, probe, probe_arguments


class FakePac:
    product = 'ums512_1h10'
    xml_text = '''<BMAConfig><File><ID>FDL</ID><Block><Base>0x5500</Base></Block></File>
    <File><ID>FDL2</ID><Block><Base>0x9efffe00</Base></Block></File></BMAConfig>'''

    def entries_for_id(self, name):
        return [types.SimpleNamespace(id=name, size=16)]

    def extract(self, entry, path):
        pathlib.Path(path).write_bytes(b'x' * entry.size)


class TransportTests(unittest.TestCase):
    def test_loader_product_and_address_are_restricted(self):
        self.assertEqual([x[1] for x in loader_entries(FakePac())], [0x5500, 0x9efffe00])
        other = FakePac()
        other.product = 'unrelated-board'
        with self.assertRaises(ProbeError):
            loader_entries(other)
        other = FakePac()
        other.xml_text = other.xml_text.replace('0x5500', '0x5501')
        with self.assertRaises(ProbeError):
            loader_entries(other)

    def test_probe_argv_contains_no_storage_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = probe_arguments(FakePac(), pathlib.Path(tmp) / 'probe', '/fake/spd_dump')
            self.assertIn('--read-only', args)
            self.assertIn('partition_list', args)
            self.assertIn('read_part', args)
            for forbidden in ['write_part', 'erase_part', 'repartition']:
                self.assertNotIn(forbidden, args)
            self.assertEqual(args[-1], 'power_off')

    def test_probe_does_not_overwrite_existing_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileExistsError):
                probe_arguments(FakePac(), tmp, '/fake/spd_dump')

    def test_completed_read_does_not_claim_identity_match(self):
        def backend(args, out, **kwargs):
            (out / 'partitions.xml').write_text('<Partitions><Partition id="boot_a"/><Partition id="super"/><Partition id="userdata"/></Partitions>')
            (out / 'boot_a-first-1MiB.bin').write_bytes(b'A' * 1048576)
        with tempfile.TemporaryDirectory() as tmp, patch('rgrotate.transport.run_bounded', backend):
            result = probe(FakePac(), pathlib.Path(tmp) / 'probe', '/fake/spd_dump')
            self.assertEqual(result['status'], 'read_completed')
            self.assertFalse(result['device_identity_verified'])
            self.assertFalse(result['writes_to_device_storage'])

    def test_incomplete_sample_is_failure(self):
        def backend(args, out, **kwargs):
            (out / 'partitions.xml').write_text('<Partitions><Partition id="boot_a"/><Partition id="super"/><Partition id="userdata"/></Partitions>')
            (out / 'boot_a-first-1MiB.bin').write_bytes(b'short')
        with tempfile.TemporaryDirectory() as tmp, patch('rgrotate.transport.run_bounded', backend):
            with self.assertRaises(ProbeError):
                probe(FakePac(), pathlib.Path(tmp) / 'probe', '/fake/spd_dump')


if __name__ == '__main__':
    unittest.main()
