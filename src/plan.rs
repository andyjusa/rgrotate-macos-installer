//! Offline, order-preserving PAC plans. A plan never grants write authority.

use crate::pac::{PacEntry, PacFile};
use anyhow::{Context, Result, bail, ensure};
use roxmltree::{Document, Node};
use serde_json::{Value, json};
use std::collections::{BTreeSet, VecDeque};
use std::sync::LazyLock;

const MAX_U32: u64 = u32::MAX as u64;
const MIB: u64 = 1024 * 1024;
const DISABLED: &str = "full-flash execution is disabled until preservation, repartition and post-write verification are validated";

fn tag(node: Node<'_, '_>, name: &str) -> bool {
    node.is_element() && node.tag_name().namespace().is_none() && node.tag_name().name() == name
}

fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|n| tag(*n, name))
}

fn child_text<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<&'a str> {
    child(node, name).and_then(|n| n.text())
}

fn text(node: Node<'_, '_>, key: &str, default: &str) -> String {
    node.attribute(key)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            node.attribute(key.to_ascii_lowercase().as_str())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| child_text(node, key).filter(|s| !s.is_empty()))
        .unwrap_or(default)
        .trim()
        .to_owned()
}

fn number(value: Option<&str>, what: &str, default: Option<u64>) -> Result<u64> {
    let value = value.unwrap_or("").trim();
    if value.is_empty() {
        return default.with_context(|| format!("missing {what}"));
    }
    let result = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse::<u64>()
    };
    result.with_context(|| format!("invalid or out-of-range {what}: {value:?}"))
}

fn name(value: &str, what: &str) -> Result<()> {
    ensure!(
        (1..=35).contains(&value.len())
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-')),
        "invalid {what}: {value:?}"
    );
    Ok(())
}

fn preserved(value: &str) -> bool {
    static NV: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^(?:[a-z]+_)?(?:fixnv|runtimenv|deltanv|calinv)[0-9]*(?:_[ab])?$")
            .unwrap()
    });
    matches!(value, "prodnv" | "miscdata" | "persist") || NV.is_match(value)
}

fn partition_table(product: Node<'_, '_>) -> Result<(Vec<Value>, Vec<Value>)> {
    let mut table = Vec::new();
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    // ElementTree's ./Partitions/Partition includes each direct Partitions node.
    for partition in product
        .children()
        .filter(|n| tag(*n, "Partitions"))
        .flat_map(|n| n.children().filter(|c| tag(*c, "Partition")))
    {
        let identifier = partition.attribute("id").unwrap_or("");
        name(identifier, "partition id")?;
        let size = number(
            partition.attribute("size"),
            &format!("partition {identifier} size"),
            None,
        )?;
        ensure!(
            size <= MAX_U32,
            "partition {identifier} size exceeds the PAC table field"
        );
        let other = partition.attribute("id2").unwrap_or("");
        if !other.is_empty() {
            name(other, "partition id2")?;
        }
        let kind = number(
            partition.attribute("type"),
            &format!("partition {identifier} type"),
            Some(0),
        )?;
        ensure!(kind <= 255, "partition {identifier} type exceeds one byte");
        let ordinal = table.len();
        table.push(json!({
            "ordinal": ordinal, "name": identifier,
            "id2": if other.is_empty() { None } else { Some(other) },
            "size_mib": size, "size_bytes": if size == MAX_U32 { None } else { Some(size * MIB) },
            "type": kind,
        }));
        if let Some((_, indexes)) = groups.iter_mut().find(|(n, _)| n == identifier) {
            indexes.push(ordinal);
        } else {
            groups.push((identifier.to_owned(), vec![ordinal]));
        }
    }
    ensure!(!table.is_empty(), "PAC product has no partition table");
    let duplicates = groups
        .into_iter()
        .filter(|(_, indexes)| indexes.len() > 1)
        .map(|(name, ordinals)| json!({"name":name, "ordinals":ordinals}))
        .collect();
    Ok((table, duplicates))
}

fn file_operations(node: Node<'_, '_>) -> Result<Vec<String>> {
    node.children()
        .filter(|n| tag(*n, "Operation") || tag(*n, "Scheme"))
        .map(|operation| {
            ["type", "Type", "name", "Name"]
                .into_iter()
                .find_map(|key| operation.attribute(key).filter(|value| !value.is_empty()))
                .map(str::to_owned)
                .context("PAC contains an operation without a name")
        })
        .collect()
}

fn remember(backups: &mut Vec<(String, String)>, key: &str, reason: &str, overwrite: bool) {
    if let Some((_, existing)) = backups.iter_mut().find(|(name, _)| name == key) {
        if overwrite {
            *existing = reason.to_owned();
        }
    } else {
        backups.push((key.to_owned(), reason.to_owned()));
    }
}

pub fn build_plan(pac: &PacFile) -> Result<Value> {
    let xml = pac.xml_text()?;
    let document = Document::parse(&xml).context("invalid PAC XML")?;
    let root = document.root_element();
    ensure!(
        tag(root, "BMAConfig"),
        "only BMAConfig PAC XML is supported"
    );
    let products: Vec<_> = root
        .children()
        .filter(|n| tag(*n, "ProductList"))
        .flat_map(|n| n.children().filter(|c| tag(*c, "Product")))
        .filter(|n| n.attribute("name") == Some(pac.product.as_str()))
        .collect();
    ensure!(
        products.len() == 1,
        "PAC product does not identify exactly one XML product"
    );
    let product = products[0];
    ensure!(
        pac.product == "ums512_1h10",
        "this installer supports RG Rotate ums512_1h10, not {:?}",
        pac.product
    );
    let scheme_name = child_text(product, "SchemeName").unwrap_or("").trim();
    let schemes: Vec<_> = root
        .children()
        .filter(|n| tag(*n, "SchemeList"))
        .flat_map(|n| n.children().filter(|c| tag(*c, "Scheme")))
        .filter(|n| n.attribute("name") == Some(scheme_name))
        .collect();
    ensure!(
        !scheme_name.is_empty() && schemes.len() == 1,
        "PAC product does not identify exactly one XML scheme"
    );
    let (table, duplicate_partitions) = partition_table(product)?;
    let partition_names: BTreeSet<_> = table
        .iter()
        .map(|item| item["name"].as_str().unwrap())
        .collect();
    let mut pending: Vec<(String, VecDeque<&PacEntry>)> = Vec::new();
    for entry in &pac.entries {
        if entry.id.is_empty() || !matches!(entry.flag, 0 | 1) {
            continue;
        }
        if let Some((_, entries)) = pending.iter_mut().find(|(id, _)| *id == entry.id) {
            entries.push_back(entry);
        } else {
            pending.push((entry.id.clone(), VecDeque::from([entry])));
        }
    }
    let mut actions = Vec::new();
    let mut loaders = Vec::new();
    let mut blockers: Vec<String> = Vec::new();
    let mut backups = Vec::new();
    for (ordinal, node) in schemes[0]
        .children()
        .filter(|n| tag(*n, "File"))
        .enumerate()
    {
        let file_id = text(node, "ID", "");
        ensure!(!file_id.is_empty(), "XML file {ordinal} has no ID");
        let entry = pending
            .iter_mut()
            .find(|(id, _)| id == &file_id)
            .and_then(|(_, entries)| entries.pop_front());
        let Some(entry) = entry else {
            ensure!(
                number(Some(&text(node, "CheckFlag", "0")), "CheckFlag", None)? != 1,
                "required XML file is missing from the PAC: {file_id}"
            );
            continue;
        };
        let block = child(node, "Block").with_context(|| format!("file {file_id} has no Block"))?;
        let file_type = text(node, "Type", "");
        let address = number(
            Some(&text(block, "Base", "0")),
            &format!("{file_id} address"),
            None,
        )?;
        let target = block.attribute("id").unwrap_or("");
        let operations = file_operations(node)?;
        let selected = entry.check_flag != 0;
        let mut action = json!({
            "ordinal": ordinal, "entry_index": entry.index, "file_id": file_id,
            "filename": entry.name, "type": file_type,
            "target": if target.is_empty() { None } else { Some(target) },
            "address": address, "size_bytes": entry.size, "pac_offset": entry.offset,
            "selected": selected, "xml_operations": operations,
        });
        if matches!(file_id.as_str(), "FDL" | "FDL2") {
            ensure!(
                entry.flag != 0 && entry.size > 0 && selected && address > 0 && address <= MAX_U32,
                "invalid required RAM loader: {file_id}"
            );
            let expected = if file_id == "FDL" {
                0x5500
            } else {
                0x9eff_fe00
            };
            ensure!(
                address == expected,
                "{file_id} load address does not match the RG Rotate profile"
            );
            action["kind"] = json!("ram_load");
            action["role"] = json!(if file_id == "FDL" { "FDL1" } else { "FDL2" });
            loaders.push(action);
            continue;
        }
        ensure!(
            !target.is_empty(),
            "file {file_id} has no named destination"
        );
        name(target, "file destination")?;
        if !partition_names.contains(target) && !matches!(target, "splloader" | "splloader_bak") {
            blockers.push(format!(
                "destination {target} is absent from the PAC partition table"
            ));
        }
        let preserve = node.attribute("backup") == Some("1") || preserved(target);
        let reason = if node.attribute("backup") == Some("1") {
            "XML backup=1"
        } else {
            "device calibration/NV/persist data"
        };
        if preserve {
            remember(&mut backups, target, reason, true);
        }
        let data_type = matches!(
            file_type.as_str(),
            "CODE2" | "YAFFS_IMG2" | "UBOOT_LOADER2" | "BOOT_LOADER2" | "CHECK_NV2" | "NV_COMM"
        );
        if file_type == "EraseFlash2" {
            ensure!(
                entry.flag == 0 && entry.size == 0,
                "erase-only entry unexpectedly contains data: {file_id}"
            );
            action["kind"] = json!("erase_partition");
        } else if data_type && entry.flag == 1 && entry.size > 0 {
            action["kind"] = json!(if preserve {
                "restore_preserved_partition"
            } else {
                "write_partition"
            });
            if matches!(target, "splloader" | "splloader_bak") {
                action["kind"] = json!("write_boot_region");
                blockers.push(format!(
                    "{target}: boot-region programming and verification need device validation"
                ));
            }
            if matches!(file_type.as_str(), "CHECK_NV2" | "NV_COMM") {
                action["kind"] = json!("merge_nv_then_write");
                blockers.push(format!(
                    "{file_id}: vendor NV-item merge is not implemented"
                ));
            }
        } else {
            action["kind"] = json!("unsupported");
            if selected {
                blockers.push(format!(
                    "{file_id}: unsupported type/manifest combination {file_type:?}"
                ));
            }
        }
        for operation in &operations {
            if selected && !matches!(operation.as_str(), "CheckBaud" | "Connect" | "Download") {
                blockers.push(format!(
                    "{file_id}: unsupported explicit operation {operation:?}"
                ));
            }
        }
        if preserve {
            action["preserve_reason"] = json!(reason);
            action["firmware_defaults_must_not_replace_device_data"] = json!(true);
        }
        actions.push(action);
    }
    let leftovers: Vec<_> = pending
        .iter()
        .flat_map(|(name, entries)| entries.iter().map(move |entry| (name, entry.index)))
        .collect();
    ensure!(
        leftovers.is_empty(),
        "PAC entries have no ordered XML match: {leftovers:?}"
    );
    ensure!(
        loaders.len() == 2 && loaders[0]["role"] == "FDL1" && loaders[1]["role"] == "FDL2",
        "PAC must contain exactly FDL1 then FDL2"
    );
    for part in &table {
        let name = part["name"].as_str().unwrap();
        if preserved(name) {
            remember(
                &mut backups,
                name,
                "device calibration/NV/persist data",
                false,
            );
        }
    }
    let mut preservation = Vec::new();
    for (name, reason) in backups {
        let sizes: BTreeSet<_> = table
            .iter()
            .filter(|part| part["name"] == name)
            .map(|part| part["size_bytes"].as_u64())
            .collect();
        let size = if sizes.len() != 1 || sizes.contains(&None) || sizes.contains(&Some(0)) {
            blockers.push(format!(
                "{name}: an exact bounded size is required before preserving device data"
            ));
            None
        } else {
            sizes.first().copied().flatten()
        };
        preservation.push(json!({
            "target": name, "size_bytes": size, "reason": reason,
            "steps": ["read_original", "read_again_and_compare", "persist_verified_backup",
                "restore_after_repartition_if_changed", "read_back_and_compare"],
        }));
    }
    if !duplicate_partitions.is_empty() {
        blockers.push("PAC partition table contains duplicate names; vendor repartition semantics must be resolved".to_owned());
    }
    let nv_config = child(product, "NVBackup");
    let nv_items: Vec<_> = nv_config.into_iter().flat_map(|nv| nv.children().filter(|n| tag(*n, "NVItem")))
        .map(|item| json!({"name": item.attribute("name").unwrap_or(""), "id": child_text(item, "ID").unwrap_or(""),
            "backup_requested": item.attribute("backup") == Some("1")})).collect();
    let poweroff = number(child_text(product, "PowerOff"), "PowerOff", Some(0))?;
    if poweroff > 1 {
        blockers.push("unsupported PowerOff value".to_owned());
    }
    blockers.push(DISABLED.to_owned());
    let mut seen = BTreeSet::new();
    blockers.retain(|message| seen.insert(message.clone()));
    Ok(json!({
        "schema_version": 1, "mode": "offline_plan", "source": {
            "product": pac.product, "container_version": pac.version,
            "firmware_version": pac.firmware, "size_bytes": pac.size,
        },
        "loaders": loaders, "partitions": table, "operations": actions,
        "duplicate_partition_names": duplicate_partitions, "preservation": preservation,
        "nv_policy": {
            "backup_requested": nv_config.is_some_and(|nv| nv.attribute("backup") == Some("1")),
            "items": nv_items,
            "policy": "preserve verified original device data; merge only when a selected NV image requires it",
        },
        "required_installation_steps": ["verify_PAC_and_plan", "load_official_FDLs_into_RAM",
            "read_device_partition_table", "verify_device_layout_and_identity", "backup_and_verify_preservation_regions",
            "resolve_repartition_policy", "execute_selected_operations_in_XML_order", "restore_and_verify_preserved_regions",
            "verify_written_images", "finalize_device"],
        "finalization": {"vendor_requests_poweroff": poweroff != 0, "automatic_reset_enabled": false},
        "execution": {"storage_writes_enabled": false, "full_flash_ready": false, "blockers": blockers},
    }))
}

/// Generic PAC replay is unimplemented, including if a caller edits JSON flags.
pub fn require_flash_ready(plan: &Value) -> Result<()> {
    let reasons = plan
        .pointer("/execution/blockers")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("; ")
        })
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| "no validated write executor".to_owned());
    bail!("device writes are disabled: {reasons}")
}
