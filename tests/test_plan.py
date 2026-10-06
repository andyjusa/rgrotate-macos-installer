"""Offline planner regressions; all fixtures are synthetic, no ROMs required."""

from __future__ import annotations

import copy
import io
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from rgrotate.plan import PlanError, build_plan, require_flash_ready


def fixture():
    root = ET.Element("BMAConfig")
    products = ET.SubElement(root, "ProductList")
    product = ET.SubElement(products, "Product", name="ums512_1h10")
    ET.SubElement(product, "SchemeName").text = "ums512_1h10"
    nv = ET.SubElement(product, "NVBackup", backup="1")
    item = ET.SubElement(nv, "NVItem", name="Calibration", backup="1")
    ET.SubElement(item, "ID").text = "0xFFFFFFFF"
    table = ET.SubElement(product, "Partitions")
    for name, size in [("prodnv", 10), ("l_fixnv1_a", 2), ("l_fixnv2_a", 2),
                       ("l_runtimenv1", 2), ("persist", 2), ("boot_a", 64),
                       ("uboot_a", 3), ("uboot_b", 3), ("super", 5600), ("metadata", 16)]:
        ET.SubElement(table, "Partition", id=name, size=str(size))
    scheme = ET.SubElement(ET.SubElement(root, "SchemeList"), "Scheme", name="ums512_1h10")
    specs = [
        ("FDL", "FDL", "", 0x5500, 60000, "fdl1.bin"),
        ("FDL2", "NAND_FDL", "", 0x9EFFFE00, 800000, "fdl2.bin"),
        ("ProdNV", "CODE2", "prodnv", 0, 10 * 1024**2, "nv.img"),
        ("BOOT", "CODE2", "boot_a", 0, 64 * 1024**2, "boot.img"),
        ("UBOOTLoader", "UBOOT_LOADER2", "uboot_a", 0, 3 * 1024**2, "same-name.img"),
        ("UBOOTLoader", "UBOOT_LOADER2", "uboot_b", 0, 3 * 1024**2, "same-name.img"),
        ("Super", "YAFFS_IMG2", "super", 0, 5600 * 1024**2, "super.img"),
        ("EraseMetadata", "EraseFlash2", "metadata", 0, 0, ""),
    ]
    entries = []
    offset = 5 * 1024**3
    for index, (file_id, kind, target, address, size, name) in enumerate(specs):
        node = ET.SubElement(scheme, "File")
        ET.SubElement(node, "ID").text = file_id
        ET.SubElement(node, "Type").text = kind
        block = ET.SubElement(node, "Block", **({"id": target} if target else {}))
        ET.SubElement(block, "Base").text = hex(address)
        ET.SubElement(node, "CheckFlag").text = "1"
        if file_id == "ProdNV":
            node.set("backup", "1")
        entries.append(SimpleNamespace(index=index, id=file_id, name=name, size=size,
                                       offset=offset if size else 0, flag=int(size > 0), check_flag=1))
        offset += size
    entries.append(SimpleNamespace(index=len(entries), id="", name="config.xml", size=100,
                                   offset=offset, flag=2, check_flag=0))
    pac = SimpleNamespace(product="ums512_1h10", version="BP_R2.0.1", firmware="test",
                          entries=entries, size=offset + 100)
    pac.xml_text = ET.tostring(root, encoding="unicode")
    return pac, root


def changed(pac, root):
    pac.xml_text = ET.tostring(root, encoding="unicode")
    return pac


class PlanTests(unittest.TestCase):
    def test_duplicate_ids_are_paired_by_occurrence_not_filename(self):
        pac, _ = fixture()
        plan = build_plan(pac)
        ops = [x for x in plan["operations"] if x["file_id"] == "UBOOTLoader"]
        self.assertEqual([(x["entry_index"], x["target"]) for x in ops], [(4, "uboot_a"), (5, "uboot_b")])
        self.assertNotEqual(ops[0]["pac_offset"], ops[1]["pac_offset"])

    def test_large_offsets_and_sizes_remain_exact(self):
        pac, _ = fixture()
        plan = build_plan(pac)
        op = next(x for x in plan["operations"] if x["target"] == "super")
        self.assertEqual(op["size_bytes"], 5872025600)
        self.assertGreater(op["pac_offset"], 2**32)
        self.assertEqual(op["pac_offset"], pac.entries[6].offset)

    def test_duplicate_partition_table_is_reported_without_silent_dedup(self):
        pac, root = fixture()
        ET.SubElement(root.find("./ProductList/Product/Partitions"), "Partition", id="l_runtimenv1", size="2")
        plan = build_plan(changed(pac, root))
        duplicates = plan["duplicate_partition_names"]
        self.assertEqual(duplicates[0]["name"], "l_runtimenv1")
        self.assertEqual(len([p for p in plan["partitions"] if p["name"] == "l_runtimenv1"]), 2)
        self.assertTrue(any("duplicate names" in x for x in plan["execution"]["blockers"]))

    def test_nv_backup_tasks_cover_slot_names_and_persist(self):
        pac, _ = fixture()
        plan = build_plan(pac)
        targets = {x["target"] for x in plan["preservation"]}
        self.assertEqual(targets, {"prodnv", "l_fixnv1_a", "l_fixnv2_a", "l_runtimenv1", "persist"})
        op = next(x for x in plan["operations"] if x["target"] == "prodnv")
        self.assertEqual(op["kind"], "restore_preserved_partition")
        self.assertTrue(op["firmware_defaults_must_not_replace_device_data"])
        self.assertFalse(any("NV-item merge" in x for x in plan["execution"]["blockers"]))

    def test_erase_is_an_explicit_operation(self):
        pac, _ = fixture()
        op = build_plan(pac)["operations"][-1]
        self.assertEqual((op["kind"], op["target"]), ("erase_partition", "metadata"))

    def test_unknown_xml_operation_blocks_execution(self):
        pac, root = fixture()
        ET.SubElement(root.find("./SchemeList/Scheme")[3], "Operation", type="VendorSecretMerge")
        plan = build_plan(changed(pac, root))
        self.assertTrue(any("VendorSecretMerge" in x for x in plan["execution"]["blockers"]))
        with self.assertRaises(PlanError):
            require_flash_ready(plan)

    def test_ram_loader_addresses_are_required_from_matching_profile(self):
        pac, root = fixture()
        root.find("./SchemeList/Scheme/File/Block/Base").text = "0x65000800"
        with self.assertRaisesRegex(PlanError, "RG Rotate profile"):
            build_plan(changed(pac, root))

    def test_missing_second_duplicate_id_is_not_reused(self):
        pac, _ = fixture()
        pac.entries.pop(5)
        with self.assertRaisesRegex(PlanError, "missing"):
            build_plan(pac)

    def test_unknown_pac_entry_is_rejected(self):
        pac, _ = fixture()
        extra = copy.copy(pac.entries[3])
        extra.id = "SURPRISE"
        extra.index = 100
        pac.entries.append(extra)
        with self.assertRaisesRegex(PlanError, "no ordered XML match"):
            build_plan(pac)

    def test_invalid_destination_is_rejected(self):
        pac, root = fixture()
        root.find("./SchemeList/Scheme")[3].find("Block").set("id", "../../userdata")
        with self.assertRaisesRegex(PlanError, "invalid file destination"):
            build_plan(changed(pac, root))

    def test_every_generated_plan_has_no_write_authority(self):
        pac, _ = fixture()
        plan = build_plan(pac)
        self.assertFalse(plan["execution"]["storage_writes_enabled"])
        with self.assertRaisesRegex(PlanError, "writes are disabled"):
            require_flash_ready(plan)


class CliIsolationTests(unittest.TestCase):
    def test_default_plan_does_not_import_transport(self):
        from rgrotate.cli import main
        pac, _ = fixture()
        with patch("rgrotate.cli.PacFile", return_value=pac), patch.dict(sys.modules, {"rgrotate.transport": None}), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(main(["synthetic.pac"]), 0)
            self.assertIn('"mode": "offline_plan"', output.getvalue())

    def test_explicit_flash_fails_before_importing_transport(self):
        from rgrotate.cli import main
        pac, _ = fixture()
        with patch("rgrotate.cli.PacFile", return_value=pac), patch.dict(sys.modules, {"rgrotate.transport": None}), \
             patch("sys.stderr", new_callable=io.StringIO) as output:
            self.assertEqual(main(["flash", "synthetic.pac", "--flash", "--full-flash"]), 2)
            self.assertIn("writes are disabled", output.getvalue())

    def test_incomplete_write_permission_is_rejected_before_pac_open(self):
        from rgrotate.cli import main
        for args in (["flash", "synthetic.pac"], ["synthetic.pac", "--flash"],
                     ["synthetic.pac", "--full-flash"], ["synthetic.pac", "--flahs"]):
            with self.subTest(args=args), patch("rgrotate.cli.PacFile") as opened, \
                 patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit):
                main(args)
            opened.assert_not_called()

    def test_dump_cannot_reach_any_transport(self):
        from rgrotate.cli import main
        pac, _ = fixture()
        with patch("rgrotate.cli.PacFile", return_value=pac), patch.dict(sys.modules, {"rgrotate.transport": None}), \
             patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(main(["dump-firmware", "synthetic.pac"]), 2)

    def test_clean_install_requires_explicit_wipe_and_output(self):
        from rgrotate.cli import main
        cases = [
            ['flash', 'synthetic.pac', '--flash', '--preserve-layout'],
            ['flash', 'synthetic.pac', '--flash', '--preserve-layout', '--wipe-data'],
            ['plan', 'synthetic.pac', '--wipe-data'],
            ['probe', 'synthetic.pac', '--wipe-data'],
        ]
        for args in cases:
            with self.subTest(args=args), patch('rgrotate.cli.PacFile') as opened, \
                 patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit):
                main(args)
            opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
