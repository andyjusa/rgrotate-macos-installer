"""Offline PAC tests: fixtures are sparse files, never multi-GiB allocations."""

from dataclasses import replace
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from rgrotate.pac import MAX_READ_BYTES, PacError, PacFile


GIB = 1 << 30
HEADER = 2124
ENTRY = 2580


def put_wide(buffer, offset, capacity, text):
    encoded = text.encode("utf-16le")
    if len(encoded) + 2 > capacity:
        raise ValueError("fixture string too long")
    buffer[offset : offset + capacity] = encoded.ljust(capacity, b"\0")


def make_pac(path, entries, *, total_size=None, version="BP_R2.0.1"):
    """Construct bytes by fixed format offsets, independently of parser helpers.

    Entry dictionaries may supply payload fragments at relative offsets. Seeking
    creates sparse holes so a >4-GiB logical fixture consumes only a few blocks.
    """
    table_end = HEADER + ENTRY * len(entries)
    if total_size is None:
        total_size = max([table_end] + [entry.get("offset", 0) + entry.get("size", 0) for entry in entries])
    header = bytearray(HEADER)
    put_wide(header, 0, 44, version)
    struct.pack_into("<II", header, 44, total_size >> 32, total_size & 0xFFFFFFFF)
    put_wide(header, 52, 512, "ums512_1h10")
    put_wide(header, 564, 512, "1.4.1")
    struct.pack_into("<II", header, 1076, len(entries), HEADER)
    struct.pack_into("<I", header, 2116, 0xFFFAFFFA)
    with path.open("wb") as output:
        output.write(header)
        for entry in entries:
            raw = bytearray(ENTRY)
            struct.pack_into("<I", raw, 0, ENTRY)
            put_wide(raw, 4, 512, entry.get("id", "image"))
            put_wide(raw, 516, 512, entry.get("name", "image.bin"))
            size = entry.get("size", 0)
            offset = entry.get("offset", 0)
            struct.pack_into("<III", raw, 1532, size >> 32, offset >> 32, size & 0xFFFFFFFF)
            struct.pack_into("<IIIII", raw, 1544, entry.get("flag", 1), 1, offset & 0xFFFFFFFF, 0, 1)
            struct.pack_into("<I", raw, 1564, 0x5500)
            output.write(raw)
        output.truncate(total_size)
        for entry in entries:
            for relative, data in entry.get("fragments", []):
                output.seek(entry["offset"] + relative)
                output.write(data)
    return path


def patch_u32(path, offset, value):
    with path.open("r+b") as output:
        output.seek(offset)
        output.write(struct.pack("<I", value))


class PacTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rgrotate-pac-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.path = self.directory / "firmware.pac"

    def small_pac(self, payload=b"firmware"):
        return make_pac(self.path, [{"size": len(payload), "offset": HEADER + ENTRY,
                                     "fragments": [(0, payload)]}])

    def test_offset_above_four_gib_extracts_exact_bytes(self):
        payload = b"payload beyond the 32-bit boundary\x00\xff"
        offset = 4 * GIB + 8192
        make_pac(self.path, [{"id": "FDL2", "name": "fdl2.bin", "size": len(payload),
                            "offset": offset, "fragments": [(0, payload)]}])
        pac = PacFile(self.path)
        entry = pac.entries[0]
        self.assertEqual(pac.size, offset + len(payload))
        self.assertEqual(entry.offset, offset)
        self.assertEqual(pac.read(entry), payload)
        target = pac.extract(entry, self.directory / "selected" / "fdl2.bin")
        self.assertEqual(target.read_bytes(), payload)
        self.assertLess(self.path.stat().st_blocks * 512, 1024 * 1024)

    def test_size_above_four_gib_and_tail_range_are_not_truncated(self):
        size = 4 * GIB + 31
        offset = HEADER + ENTRY
        tail = b"this is the actual >4GiB tail"
        make_pac(self.path, [{"size": size, "offset": offset,
                            "fragments": [(0, b"BEGIN"), (size - len(tail), tail)]}])
        pac = PacFile(self.path)
        entry = pac.entries[0]
        self.assertEqual(entry.size, size)
        self.assertEqual(pac.read_range(entry, size - len(tail), len(tail)), tail)
        self.assertEqual(pac.read_range(entry, 0, 5), b"BEGIN")
        with self.assertRaisesRegex(PacError, "in-memory"):
            pac.read(entry)
        chunks = pac.iter_chunks(entry, 16)
        self.assertEqual(next(chunks), b"BEGIN" + bytes(11))
        self.assertEqual(next(chunks), bytes(16))
        chunks.close()
        self.assertLess(self.path.stat().st_blocks * 512, 1024 * 1024)

    def test_stream_reads_the_whole_large_sparse_entry_without_writing_it(self):
        size = 4 * GIB + 31
        make_pac(self.path, [{"size": size, "offset": HEADER + ENTRY,
                            "fragments": [(size - 4, b"TAIL")]}])
        pac = PacFile(self.path)
        received = 0
        last = b""
        for chunk in pac.iter_chunks(pac.entries[0], MAX_READ_BYTES):
            received += len(chunk)
            last = chunk
        self.assertEqual(received, size)
        self.assertEqual(last[-4:], b"TAIL")
        self.assertLess(self.path.stat().st_blocks * 512, 1024 * 1024)

    def test_xml_above_four_gib_utf16_and_utf8(self):
        text = '<?xml version="1.0"?><BMAConfig><ProductList><Product name="rotate"/></ProductList></BMAConfig>'
        offset = 4 * GIB + 4096
        for encoding in ("utf-16", "utf-16le", "utf-8-sig"):
            with self.subTest(encoding=encoding):
                raw = (text + "\0").encode(encoding)
                make_pac(self.path, [{"id": "", "name": "config.XML", "flag": 2,
                                     "size": len(raw), "offset": offset, "fragments": [(0, raw)]}])
                pac = PacFile(self.path)
                self.assertEqual(pac.xml_text, text)
                self.assertEqual(pac.xml_root.tag, "BMAConfig")

    def test_duplicate_ids_and_names_keep_both_payloads(self):
        start = HEADER + 2 * ENTRY
        make_pac(self.path, [
            {"id": "UBOOTLoader", "name": "uboot.img", "size": 1, "offset": start, "fragments": [(0, b"a")]},
            {"id": "UBOOTLoader", "name": "uboot.img", "size": 1, "offset": start + 1, "fragments": [(0, b"b")]},
        ])
        pac = PacFile(self.path)
        self.assertEqual(len(pac.entries_for_id("UBOOTLoader")), 2)
        self.assertEqual([pac.read(entry) for entry in pac.entries], [b"a", b"b"])
        self.assertEqual([entry.index for entry in pac.entries], [0, 1])

    def test_unknown_and_legacy_version_are_rejected(self):
        for version in ("BP_R1.0.0", "BP_R2.0.2", "not PAC"):
            with self.subTest(version=version):
                make_pac(self.path, [{"flag": 0}], version=version)
                with self.assertRaisesRegex(PacError, "Unsupported PAC version"):
                    PacFile(self.path)

    def test_invalid_magic_and_header_size(self):
        self.small_pac()
        patch_u32(self.path, 2116, 0)
        with self.assertRaisesRegex(PacError, "magic"):
            PacFile(self.path)
        self.small_pac()
        patch_u32(self.path, 44, 1)
        with self.assertRaisesRegex(PacError, "size mismatch"):
            PacFile(self.path)

    def test_header_and_table_truncation(self):
        self.path.write_bytes(bytes(HEADER - 1))
        with self.assertRaisesRegex(PacError, "too small"):
            PacFile(self.path)
        for position, value in ((1076, 0xFFFFFFFF), (1080, HEADER - 1), (1080, 0xFFFFFFFF)):
            with self.subTest(position=position, value=value):
                self.small_pac()
                patch_u32(self.path, position, value)
                with self.assertRaises(PacError):
                    PacFile(self.path)
        self.small_pac()
        patch_u32(self.path, 1076, 2)
        with self.assertRaisesRegex(PacError, "table extends"):
            PacFile(self.path)

    def test_entry_structure_and_address_count(self):
        for position, value in ((HEADER, ENTRY - 4), (HEADER + 1560, 6), (HEADER + 1544, 3)):
            with self.subTest(position=position):
                self.small_pac()
                patch_u32(self.path, position, value)
                with self.assertRaises(PacError):
                    PacFile(self.path)

    def test_payload_range_bounds_and_overflow(self):
        for position, value in ((1540, 0xFFFFFFFF), (1532, 0xFFFFFFFF), (1536, 0xFFFFFFFF), (1552, 0)):
            with self.subTest(position=position):
                self.small_pac()
                patch_u32(self.path, HEADER + position, value)
                with self.assertRaises(PacError):
                    PacFile(self.path)

    def test_overlapping_ranges_rejected(self):
        start = HEADER + 2 * ENTRY
        make_pac(self.path, [{"size": 2, "offset": start}, {"size": 2, "offset": start + 1}])
        with self.assertRaisesRegex(PacError, "Overlapping"):
            PacFile(self.path)

    def test_archive_path_traversal_rejected(self):
        for name in ("../escape", "a/../escape", "/absolute", "..", ".", "C:\\escape", "a\\escape", "x\ny"):
            with self.subTest(name=name):
                make_pac(self.path, [{"name": name, "size": 1, "offset": HEADER + ENTRY}])
                with self.assertRaisesRegex(PacError, "Unsafe filename"):
                    PacFile(self.path)

    def test_extract_refuses_existing_files_and_symlinks(self):
        self.small_pac()
        pac = PacFile(self.path)
        victim = self.directory / "victim"
        victim.write_bytes(b"KEEP")
        link = self.directory / "link"
        link.symlink_to(victim)
        for target in (victim, link, self.path):
            with self.subTest(target=target):
                with self.assertRaises(FileExistsError):
                    pac.extract(pac.entries[0], target)
        self.assertEqual(victim.read_bytes(), b"KEEP")
        self.assertTrue(link.is_symlink())

    def test_late_existing_target_does_not_get_overwritten(self):
        self.small_pac()
        pac = PacFile(self.path)
        target = self.directory / "target"
        real_link = os.link

        def racing_link(source, destination):
            target.write_bytes(b"KEEP")
            return real_link(source, destination)

        with mock.patch("rgrotate.pac.os.link", side_effect=racing_link):
            with self.assertRaises(FileExistsError):
                pac.extract(pac.entries[0], target)
        self.assertEqual(target.read_bytes(), b"KEEP")
        self.assertFalse(list(self.directory.glob(".rgrotate-*")))

    def test_changed_or_truncated_source_leaves_no_output(self):
        self.small_pac()
        pac = PacFile(self.path)
        with self.path.open("r+b") as output:
            output.truncate(self.path.stat().st_size - 1)
        target = self.directory / "target"
        with self.assertRaisesRegex(PacError, "changed"):
            pac.extract(pac.entries[0], target)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.directory.glob(".rgrotate-*")))

    def test_eof_during_stream_is_failure(self):
        # Exceed the platform's buffered-file read-ahead window.
        self.small_pac(b"x" * (2 * 1024 * 1024))
        pac = PacFile(self.path)
        chunks = pac.iter_chunks(pac.entries[0], 8192)
        self.assertEqual(len(next(chunks)), 8192)
        with self.path.open("r+b") as output:
            output.truncate(HEADER + ENTRY + 8192)
        with self.assertRaisesRegex(PacError, "EOF"):
            list(chunks)

    def test_write_failure_does_not_leave_partial_output(self):
        self.small_pac()
        pac = PacFile(self.path)
        target = self.directory / "target"
        with mock.patch("rgrotate.pac.os.fsync", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                pac.extract(pac.entries[0], target)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.directory.glob(".rgrotate-*")))

    def test_changed_source_replacement_is_detected(self):
        self.small_pac()
        pac = PacFile(self.path)
        new = self.directory / "replacement"
        new.write_bytes(self.path.read_bytes())
        new.replace(self.path)
        with self.assertRaisesRegex(PacError, "changed"):
            pac.read(pac.entries[0])

    def test_fifo_source_is_rejected_without_waiting_for_writer(self):
        os.mkfifo(self.path)
        with self.assertRaisesRegex(PacError, "regular file"):
            PacFile(self.path)

    def test_foreign_or_modified_entry_and_invalid_ranges_rejected(self):
        self.small_pac()
        pac = PacFile(self.path)
        entry = pac.entries[0]
        for foreign in (replace(entry, offset=0), PacFile(self.path).entries[0]):
            with self.assertRaisesRegex(PacError, "does not belong"):
                pac.read(foreign)
        for offset, length in ((-1, 1), (0, -1), (entry.size, 1), (1 << 64, 1), (1, 1 << 64)):
            with self.subTest(offset=offset, length=length):
                with self.assertRaises(PacError):
                    pac.read_range(entry, offset, length)
        for size in (0, -1, MAX_READ_BYTES + 1):
            with self.assertRaises(PacError):
                next(pac.iter_chunks(entry, size))

    def test_operation_only_entry_is_not_extracted(self):
        make_pac(self.path, [{"id": "EraseMetadata", "name": "", "flag": 0}])
        pac = PacFile(self.path)
        self.assertEqual(pac.entries[0].size, 0)
        self.assertEqual(pac.entries[0].addresses, (0x5500,))
        with self.assertRaisesRegex(PacError, "operation"):
            pac.extract(pac.entries[0], self.directory / "operation")

    def test_ambiguous_xml_and_entity_expansion_rejected(self):
        start = HEADER + 2 * ENTRY
        make_pac(self.path, [{"name": "a.xml", "size": 4, "offset": start},
                            {"name": "b.xml", "size": 4, "offset": start + 4}])
        with self.assertRaisesRegex(PacError, "found 2"):
            PacFile(self.path).xml_text
        xml = b'<!DOCTYPE a [<!ENTITY x "bad">]><a>&x;</a>'
        make_pac(self.path, [{"name": "a.xml", "size": len(xml), "offset": HEADER + ENTRY,
                            "fragments": [(0, xml)]}])
        with self.assertRaisesRegex(PacError, "DTD"):
            PacFile(self.path).xml_text


@unittest.skipUnless(os.environ.get("RGROTATE_TEST_PAC") and os.environ.get("RGROTATE_TEST_MANIFEST"),
                     "Set RGROTATE_TEST_PAC and RGROTATE_TEST_MANIFEST for read-only firmware integration")
class RealPacTests(unittest.TestCase):
    def test_all_entries_match_independent_manifest(self):
        pac = PacFile(os.environ["RGROTATE_TEST_PAC"])
        manifest = json.loads(Path(os.environ["RGROTATE_TEST_MANIFEST"]).read_text())
        self.assertEqual((pac.version, pac.product, pac.firmware, pac.size),
                         (manifest["version"], manifest["product"], manifest["firmware"], manifest["size"]))
        self.assertEqual(len(pac.entries), len(manifest["entries"]))
        for actual, expected in zip(pac.entries, manifest["entries"]):
            with self.subTest(index=actual.index):
                self.assertEqual((actual.id, actual.name, actual.size, actual.offset, actual.flag, actual.check_flag),
                                 (expected["id"], expected["file"], expected["size"], expected["offset"], expected["data"], expected["required"]))
        self.assertEqual(len(pac.entries_for_id("UBOOTLoader")), 2)
        self.assertEqual(pac.xml_root.tag, "BMAConfig")
        xml_entry = next(entry for entry in pac.entries if entry.name.lower().endswith(".xml"))
        # Compare extraction with a direct seek/read independently of parser IO.
        with pac.path.open("rb") as source:
            source.seek(xml_entry.offset)
            expected_xml = source.read(xml_entry.size)
        with tempfile.TemporaryDirectory(prefix="rgrotate-real-pac-test-") as directory:
            target = pac.extract(xml_entry, Path(directory) / "config.xml")
            self.assertEqual(target.read_bytes(), expected_xml)


if __name__ == "__main__":
    unittest.main()
