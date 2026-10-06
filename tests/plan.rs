#[path = "pac_support/mod.rs"]
mod support;
use rgrotate::pac::PacFile;
use rgrotate::plan::{build_plan, require_flash_ready};
use serde_json::{Value, json};
use support::{FixtureEntry, write_fixture};
use tempfile::tempdir;

const MIB: u64 = 1024 * 1024;

fn fixture() -> (Vec<FixtureEntry>, String) {
    let partitions = [
        ("prodnv", 10),
        ("l_fixnv1_a", 2),
        ("l_fixnv2_a", 2),
        ("l_runtimenv1", 2),
        ("persist", 2),
        ("boot_a", 64),
        ("uboot_a", 3),
        ("uboot_b", 3),
        ("super", 5600),
        ("metadata", 16),
    ];
    let specs = [
        ("FDL", "FDL", "", 0x5500u64, 60000, "fdl1.bin"),
        ("FDL2", "NAND_FDL", "", 0x9eff_fe00, 800000, "fdl2.bin"),
        ("ProdNV", "CODE2", "prodnv", 0, 10 * MIB, "nv.img"),
        ("BOOT", "CODE2", "boot_a", 0, 64 * MIB, "boot.img"),
        (
            "UBOOTLoader",
            "UBOOT_LOADER2",
            "uboot_a",
            0,
            3 * MIB,
            "same-name.img",
        ),
        (
            "UBOOTLoader",
            "UBOOT_LOADER2",
            "uboot_b",
            0,
            3 * MIB,
            "same-name.img",
        ),
        ("Super", "YAFFS_IMG2", "super", 0, 5600 * MIB, "super.img"),
        ("EraseMetadata", "EraseFlash2", "metadata", 0, 0, ""),
    ];
    let mut xml = "<BMAConfig><ProductList><Product name=\"ums512_1h10\"><SchemeName>ums512_1h10</SchemeName><NVBackup backup=\"1\"><NVItem name=\"Calibration\" backup=\"1\"><ID>0xFFFFFFFF</ID></NVItem></NVBackup><Partitions>".to_owned();
    for (name, size) in partitions {
        xml.push_str(&format!("<Partition id=\"{name}\" size=\"{size}\"/>"));
    }
    xml.push_str("</Partitions></Product></ProductList><SchemeList><Scheme name=\"ums512_1h10\">");
    let mut entries = Vec::new();
    for (index, (id, kind, target, address, size, name)) in specs.into_iter().enumerate() {
        let mut entry = if size == 0 {
            FixtureEntry::operation(id)
        } else {
            FixtureEntry::file(id, name, b"")
        };
        entry.size = size;
        if index == 0 {
            entry.offset = Some(5 * 1024 * MIB);
        }
        entries.push(entry);
        let backup = if id == "ProdNV" { " backup=\"1\"" } else { "" };
        let attribute = if target.is_empty() {
            String::new()
        } else {
            format!(" id=\"{target}\"")
        };
        xml.push_str(&format!("<File{backup}><ID>{id}</ID><Type>{kind}</Type><Block{attribute}><Base>0x{address:x}</Base></Block><CheckFlag>1</CheckFlag></File>"));
    }
    xml.push_str("</Scheme></SchemeList></BMAConfig>");
    (entries, xml)
}

fn plan(entries: &[FixtureEntry], xml: &str) -> anyhow::Result<Value> {
    let dir = tempdir()?;
    let path = dir.path().join("firmware.pac");
    let mut entries = entries.to_vec();
    let mut config = FixtureEntry::file("", "config.xml", xml.as_bytes());
    config.flag = 2;
    config.check_flag = 0;
    entries.push(config);
    write_fixture(&path, &entries);
    build_plan(&PacFile::new(path)?)
}

fn blockers(plan: &Value) -> Vec<&str> {
    plan["execution"]["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect()
}

#[test]
fn repeated_ids_are_paired_by_occurrence_and_sizes_keep_64_bits() {
    let (entries, xml) = fixture();
    let value = plan(&entries, &xml).unwrap();
    let operations = value["operations"].as_array().unwrap();
    let repeated: Vec<_> = operations
        .iter()
        .filter(|op| op["file_id"] == "UBOOTLoader")
        .collect();
    assert_eq!(repeated.len(), 2);
    assert_eq!(repeated[0]["entry_index"], 4);
    assert_eq!(repeated[0]["target"], "uboot_a");
    assert_eq!(repeated[1]["entry_index"], 5);
    assert_eq!(repeated[1]["target"], "uboot_b");
    assert_ne!(repeated[0]["pac_offset"], repeated[1]["pac_offset"]);
    let super_image = operations
        .iter()
        .find(|op| op["target"] == "super")
        .unwrap();
    assert_eq!(super_image["size_bytes"], 5872025600u64);
    assert!(super_image["pac_offset"].as_u64().unwrap() > u32::MAX as u64);
    assert_eq!(value["loaders"][0]["role"], "FDL1");
    assert_eq!(value["loaders"][1]["role"], "FDL2");
}

#[test]
fn duplicated_partition_rows_remain_visible_and_block_execution() {
    let (entries, xml) = fixture();
    let xml = xml.replace(
        "</Partitions>",
        "<Partition id=\"l_runtimenv1\" size=\"2\"/></Partitions>",
    );
    let value = plan(&entries, &xml).unwrap();
    assert_eq!(
        value["duplicate_partition_names"][0]["name"],
        "l_runtimenv1"
    );
    assert_eq!(
        value["partitions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["name"] == "l_runtimenv1")
            .count(),
        2
    );
    assert!(
        blockers(&value)
            .iter()
            .any(|m| m.contains("duplicate names"))
    );
    assert!(require_flash_ready(&value).is_err());
}

#[test]
fn calibration_nv_preservation_and_erase_are_explicit() {
    let (entries, xml) = fixture();
    let value = plan(&entries, &xml).unwrap();
    let names: Vec<_> = value["preservation"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["target"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "prodnv",
            "l_fixnv1_a",
            "l_fixnv2_a",
            "l_runtimenv1",
            "persist"
        ]
    );
    assert_eq!(
        value["operations"][0]["kind"],
        "restore_preserved_partition"
    );
    assert_eq!(
        value["operations"][0]["firmware_defaults_must_not_replace_device_data"],
        true
    );
    assert!(!blockers(&value).iter().any(|m| m.contains("NV-item merge")));
    assert_eq!(
        value["operations"].as_array().unwrap().last().unwrap()["kind"],
        "erase_partition"
    );
    assert_eq!(value["nv_policy"]["items"][0]["id"], "0xFFFFFFFF");
}

#[test]
fn vendor_operations_keep_order_and_unknown_ones_block_execution() {
    let (entries, xml) = fixture();
    let xml = xml.replace("<ID>BOOT</ID>", "<ID>BOOT</ID><Operation type=\"Connect\"/><Scheme name=\"VendorSecretMerge\"/><Operation Type=\"Download\"/>");
    let value = plan(&entries, &xml).unwrap();
    let boot = value["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| op["file_id"] == "BOOT")
        .unwrap();
    assert_eq!(
        boot["xml_operations"],
        json!(["Connect", "VendorSecretMerge", "Download"])
    );
    assert!(
        blockers(&value)
            .iter()
            .any(|m| m.contains("VendorSecretMerge"))
    );
    assert!(require_flash_ready(&value).is_err());
    assert!(plan(&entries, &xml.replace("name=\"VendorSecretMerge\"", "")).is_err());
}

#[test]
fn loader_profile_addresses_selection_and_order_are_required() {
    let (entries, xml) = fixture();
    assert!(plan(&entries, &xml.replace("0x5500", "0x65000800")).is_err());
    assert!(plan(&entries, &xml.replace("0x5500", "0x100000000")).is_err());
    let mut deselected = entries.clone();
    deselected[0].check_flag = 0;
    assert!(plan(&deselected, &xml).is_err());
    let swapped = xml
        .replace("<ID>FDL</ID>", "<ID>SWAP</ID>")
        .replace("<ID>FDL2</ID>", "<ID>FDL</ID>")
        .replace("<ID>SWAP</ID>", "<ID>FDL2</ID>")
        .replace("0x5500", "swap")
        .replace("0x9efffe00", "0x5500")
        .replace("swap", "0x9efffe00");
    assert!(plan(&entries, &swapped).is_err());
}

#[test]
fn missing_duplicate_and_unmapped_manifest_entries_are_rejected() {
    let (entries, xml) = fixture();
    let mut missing = entries.clone();
    missing.remove(5);
    assert!(
        plan(&missing, &xml)
            .unwrap_err()
            .to_string()
            .contains("missing")
    );
    let mut extra = entries.clone();
    extra.push(FixtureEntry::file("SURPRISE", "extra.bin", b"x"));
    assert!(
        plan(&extra, &xml)
            .unwrap_err()
            .to_string()
            .contains("no ordered XML match")
    );
}

#[test]
fn optional_xml_without_binary_payload_is_skipped_but_required_is_rejected() {
    let (entries, xml) = fixture();
    let optional = xml.replace(
        "</Scheme>",
        "<File><ID>Absent</ID><CheckFlag>0</CheckFlag></File></Scheme>",
    );
    assert!(plan(&entries, &optional).is_ok());
    assert!(plan(&entries, &optional.replace("<CheckFlag>0", "<CheckFlag>1")).is_err());
}

#[test]
fn malformed_destinations_partition_fields_and_xml_structure_are_rejected() {
    let (entries, xml) = fixture();
    for replacement in ["../../userdata", "space here", "", "超过范围"] {
        let changed = xml.replace(
            "<Block id=\"boot_a\"",
            &format!("<Block id=\"{replacement}\""),
        );
        assert!(plan(&entries, &changed).is_err());
    }
    for replacement in ["-1", "4294967296", "18446744073709551616", "not-a-number"] {
        assert!(
            plan(
                &entries,
                &xml.replacen("size=\"10\"", &format!("size=\"{replacement}\""), 1)
            )
            .is_err()
        );
    }
    assert!(
        plan(
            &entries,
            &xml.replace("id=\"prodnv\" size", "id=\"prodnv\" type=\"256\" size")
        )
        .is_err()
    );
    assert!(
        plan(
            &entries,
            &xml.replace("<BMAConfig>", "<BMAConfig xmlns=\"wrong\">")
        )
        .is_err()
    );
    assert!(
        plan(
            &entries,
            &xml.replace("<SchemeName>ums512_1h10</SchemeName>", "")
        )
        .is_err()
    );
    assert!(
        plan(
            &entries,
            &xml.replace("<Block id=\"boot_a\"><Base>0x0</Base></Block>", "")
        )
        .is_err()
    );
}

#[test]
fn unsupported_types_and_nv_merges_are_never_silently_enabled() {
    let (entries, xml) = fixture();
    let unsupported = xml.replace(
        "<ID>BOOT</ID><Type>CODE2</Type>",
        "<ID>BOOT</ID><Type>UNKNOWN_TYPE</Type>",
    );
    let value = plan(&entries, &unsupported).unwrap();
    assert!(blockers(&value).iter().any(|m| m.contains("UNKNOWN_TYPE")));
    let mut deselected = entries.clone();
    deselected[3].check_flag = 0;
    assert!(
        !blockers(&plan(&deselected, &unsupported).unwrap())
            .iter()
            .any(|m| m.contains("UNKNOWN_TYPE"))
    );
    let merge = xml.replace(
        "<ID>ProdNV</ID><Type>CODE2</Type>",
        "<ID>ProdNV</ID><Type>CHECK_NV2</Type>",
    );
    let value = plan(&entries, &merge).unwrap();
    assert_eq!(value["operations"][0]["kind"], "merge_nv_then_write");
    assert!(blockers(&value).iter().any(|m| m.contains("NV-item merge")));
}

#[test]
fn unbounded_calibration_and_poweroff_values_create_blockers() {
    let (entries, xml) = fixture();
    let xml = xml
        .replacen("size=\"10\"", "size=\"4294967295\"", 1)
        .replace("</Product>", "<PowerOff>2</PowerOff></Product>");
    let value = plan(&entries, &xml).unwrap();
    assert!(value["preservation"][0]["size_bytes"].is_null());
    assert!(
        blockers(&value)
            .iter()
            .any(|m| m.contains("exact bounded size"))
    );
    assert!(blockers(&value).iter().any(|m| m.contains("PowerOff")));
    assert_eq!(value["finalization"]["automatic_reset_enabled"], false);
}

#[test]
fn generic_write_authority_cannot_be_enabled_by_editing_plan_flags() {
    let (entries, xml) = fixture();
    let mut value = plan(&entries, &xml).unwrap();
    assert_eq!(value["execution"]["storage_writes_enabled"], false);
    assert!(require_flash_ready(&value).is_err());
    value["execution"]["storage_writes_enabled"] = json!(true);
    value["execution"]["full_flash_ready"] = json!(true);
    assert!(require_flash_ready(&value).is_err());
}

#[test]
fn real_pac_plan_matches_independent_python_reference_when_supplied() {
    let (Ok(path), Ok(expected)) = (
        std::env::var("RGROTATE_TEST_PAC"),
        std::env::var("RGROTATE_TEST_PLAN"),
    ) else {
        return;
    };
    let pac = PacFile::new(path).unwrap();
    let actual = build_plan(&pac).unwrap();
    let expected: Value = serde_json::from_slice(&std::fs::read(expected).unwrap()).unwrap();
    assert_eq!(actual, expected);
}
