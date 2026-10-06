"""Offline, order-preserving installation plans for RG Rotate PAC archives.

This module does not import USB code or execute commands. A plan describes the
vendor archive; it is not authorization to perform its operations.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
import re
import xml.etree.ElementTree as ET


class PlanError(ValueError):
    """The archive cannot be mapped to an unambiguous RG Rotate plan."""


_NAME = re.compile(r"[A-Za-z0-9_.-]{1,35}\Z")
_MAX_U32 = 0xFFFFFFFF
_MIB = 1024 * 1024
_DATA_TYPES = {"CODE2", "YAFFS_IMG2", "UBOOT_LOADER2", "BOOT_LOADER2", "CHECK_NV2", "NV_COMM"}
_READ_ONLY_API_VERSION = 1


def _number(text: str | None, what: str, *, default: int | None = None) -> int:
    if text is None or not text.strip():
        if default is not None:
            return default
        raise PlanError(f"missing {what}")
    text = text.strip()
    try:
        value = int(text, 16 if text.lower().startswith("0x") else 10)
    except ValueError as exc:
        raise PlanError(f"invalid {what}: {text!r}") from exc
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise PlanError(f"out-of-range {what}: {text!r}")
    return value


def _text(node: ET.Element, key: str, default: str = "") -> str:
    return (node.get(key) or node.get(key.lower()) or node.findtext(key) or default).strip()


def _name(value: str, what: str) -> str:
    if not _NAME.fullmatch(value):
        raise PlanError(f"invalid {what}: {value!r}")
    return value


def _is_preserved_partition(name: str) -> bool:
    return name in {"prodnv", "miscdata", "persist"} or bool(
        re.fullmatch(r"(?:[a-z]+_)?(?:fixnv|runtimenv|deltanv|calinv)\d*(?:_[ab])?", name)
    )


def _partition_table(product: ET.Element) -> tuple[list[dict], list[dict]]:
    result = []
    for ordinal, node in enumerate(product.findall("./Partitions/Partition")):
        name = _name(node.get("id", ""), "partition id")
        size_mib = _number(node.get("size"), f"partition {name} size")
        if size_mib > _MAX_U32:
            raise PlanError(f"partition {name} size exceeds the PAC table field")
        other = node.get("id2", "")
        if other:
            _name(other, "partition id2")
        entry_type = _number(node.get("type"), f"partition {name} type", default=0)
        if entry_type > 255:
            raise PlanError(f"partition {name} type exceeds one byte")
        result.append({
            "ordinal": ordinal, "name": name, "id2": other or None,
            "size_mib": size_mib,
            "size_bytes": None if size_mib == _MAX_U32 else size_mib * _MIB,
            "type": entry_type,
        })
    if not result:
        raise PlanError("PAC product has no partition table")
    groups = defaultdict(list)
    for item in result:
        groups[item["name"]].append(item["ordinal"])
    duplicates = [{"name": name, "ordinals": indexes}
                  for name, indexes in groups.items() if len(indexes) > 1]
    return result, duplicates


def _file_operations(node: ET.Element) -> list[str]:
    operations = []
    for child in node:
        if child.tag in {"Operation", "Scheme"}:
            name = child.get("type") or child.get("Type") or child.get("name") or child.get("Name")
            if not name:
                raise PlanError("PAC contains an operation without a name")
            operations.append(name)
    return operations


def build_plan(pac) -> dict:
    """Parse a validated PacFile into a JSON-serializable, non-executable plan.

    Repeated binary file IDs are paired with XML occurrences in their original
    order. Filenames are descriptive only: two entries may use the same name.
    Unsupported behavior is recorded as a blocker, never silently discarded.
    """
    try:
        root = ET.fromstring(pac.xml_text)
    except ET.ParseError as exc:
        raise PlanError(f"invalid PAC XML: {exc}") from exc
    if root.tag != "BMAConfig":
        raise PlanError("only BMAConfig PAC XML is supported")
    products = root.findall("./ProductList/Product")
    matches = [node for node in products if node.get("name") == pac.product]
    if len(matches) != 1:
        raise PlanError("PAC product does not identify exactly one XML product")
    product = matches[0]
    if pac.product != "ums512_1h10":
        raise PlanError(f"this installer supports RG Rotate ums512_1h10, not {pac.product!r}")
    scheme_name = product.findtext("SchemeName", "").strip()
    schemes = [node for node in root.findall("./SchemeList/Scheme") if node.get("name") == scheme_name]
    if not scheme_name or len(schemes) != 1:
        raise PlanError("PAC product does not identify exactly one XML scheme")
    table, duplicate_partitions = _partition_table(product)
    partition_names = {item["name"] for item in table}

    pending = defaultdict(deque)
    for entry in pac.entries:
        # Container metadata, including the XML, is never a flash target.
        if entry.id and entry.flag in {0, 1}:
            pending[entry.id].append(entry)

    actions, loaders, blockers, backups = [], [], [], {}
    for ordinal, node in enumerate(schemes[0].findall("File")):
        file_id = _text(node, "ID")
        if not file_id:
            raise PlanError(f"XML file {ordinal} has no ID")
        entries = pending[file_id]
        if not entries:
            # The PAC binary manifest, not an XML UI default, selects optional
            # files. An XML-mandatory loader/data entry must still be present.
            if _number(_text(node, "CheckFlag", "0"), "CheckFlag") == 1:
                raise PlanError(f"required XML file is missing from the PAC: {file_id}")
            continue
        entry = entries.popleft()
        block = node.find("Block")
        if block is None:
            raise PlanError(f"file {file_id} has no Block")
        file_type = _text(node, "Type")
        address = _number(_text(block, "Base", "0"), f"{file_id} address")
        target = block.get("id", "")
        requested_operations = _file_operations(node)
        selected = bool(entry.check_flag)
        action = {
            "ordinal": ordinal, "entry_index": entry.index, "file_id": file_id,
            "filename": entry.name, "type": file_type, "target": target or None,
            "address": address, "size_bytes": entry.size, "pac_offset": entry.offset,
            "selected": selected, "xml_operations": requested_operations,
        }
        if file_id in {"FDL", "FDL2"}:
            if not entry.flag or not entry.size or not selected or address > _MAX_U32 or address == 0:
                raise PlanError(f"invalid required RAM loader: {file_id}")
            expected = 0x5500 if file_id == "FDL" else 0x9EFFFE00
            if address != expected:
                raise PlanError(f"{file_id} load address does not match the RG Rotate profile")
            action.update(kind="ram_load", role="FDL1" if file_id == "FDL" else "FDL2")
            loaders.append(action)
            continue
        if not target:
            raise PlanError(f"file {file_id} has no named destination")
        _name(target, "file destination")
        if target not in partition_names and target not in {"splloader", "splloader_bak"}:
            blockers.append(f"destination {target} is absent from the PAC partition table")
        preserve = node.get("backup") == "1" or _is_preserved_partition(target)
        if preserve:
            backups[target] = "XML backup=1" if node.get("backup") == "1" else "device calibration/NV/persist data"
        if file_type == "EraseFlash2":
            if entry.flag != 0 or entry.size:
                raise PlanError(f"erase-only entry unexpectedly contains data: {file_id}")
            action["kind"] = "erase_partition"
        elif file_type in _DATA_TYPES and entry.flag == 1 and entry.size > 0:
            action["kind"] = "restore_preserved_partition" if preserve else "write_partition"
            if target in {"splloader", "splloader_bak"}:
                action["kind"] = "write_boot_region"
                blockers.append(f"{target}: boot-region programming and verification need device validation")
            if file_type in {"CHECK_NV2", "NV_COMM"}:
                action["kind"] = "merge_nv_then_write"
                blockers.append(f"{file_id}: vendor NV-item merge is not implemented")
        else:
            action["kind"] = "unsupported"
            if selected:
                blockers.append(f"{file_id}: unsupported type/manifest combination {file_type!r}")
        for operation in requested_operations:
            if operation not in {"CheckBaud", "Connect", "Download"}:
                if selected:
                    blockers.append(f"{file_id}: unsupported explicit operation {operation!r}")
        if preserve:
            action["preserve_reason"] = backups[target]
            action["firmware_defaults_must_not_replace_device_data"] = True
        actions.append(action)

    leftovers = [(name, entry.index) for name, entries in pending.items() for entry in entries]
    if leftovers:
        raise PlanError(f"PAC entries have no ordered XML match: {leftovers}")
    if [item["role"] for item in loaders] != ["FDL1", "FDL2"]:
        raise PlanError("PAC must contain exactly FDL1 then FDL2")

    # Preserve all unique device-specific regions across repartitioning, even
    # when the PAC does not provide an image for that region.
    for part in table:
        if _is_preserved_partition(part["name"]):
            backups.setdefault(part["name"], "device calibration/NV/persist data")
    sizes = defaultdict(set)
    for part in table:
        sizes[part["name"]].add(part["size_bytes"])
    preservation = []
    for name, reason in backups.items():
        if len(sizes[name]) != 1 or None in sizes[name] or 0 in sizes[name]:
            blockers.append(f"{name}: an exact bounded size is required before preserving device data")
            size = None
        else:
            size = next(iter(sizes[name]))
        preservation.append({
            "target": name, "size_bytes": size, "reason": reason,
            "steps": ["read_original", "read_again_and_compare", "persist_verified_backup",
                      "restore_after_repartition_if_changed", "read_back_and_compare"],
        })
    if duplicate_partitions:
        blockers.append("PAC partition table contains duplicate names; vendor repartition semantics must be resolved")
    nv_config = product.find("NVBackup")
    nv_items = []
    if nv_config is not None:
        for item in nv_config.findall("NVItem"):
            nv_items.append({"name": item.get("name", ""), "id": item.findtext("ID", ""),
                             "backup_requested": item.get("backup") == "1"})
    finish_poweroff = _number(product.findtext("PowerOff"), "PowerOff", default=0)
    if finish_poweroff not in {0, 1}:
        blockers.append("unsupported PowerOff value")
    blockers.append("full-flash execution is disabled until preservation, repartition and post-write verification are validated")
    return {
        "schema_version": _READ_ONLY_API_VERSION,
        "mode": "offline_plan", "source": {
            "product": pac.product, "container_version": pac.version,
            "firmware_version": pac.firmware, "size_bytes": pac.size,
        },
        "loaders": loaders, "partitions": table, "operations": actions,
        "duplicate_partition_names": duplicate_partitions,
        "preservation": preservation,
        "nv_policy": {
            "backup_requested": nv_config is not None and nv_config.get("backup") == "1",
            "items": nv_items,
            "policy": "preserve verified original device data; merge only when a selected NV image requires it",
        },
        "required_installation_steps": [
            "verify_PAC_and_plan", "load_official_FDLs_into_RAM", "read_device_partition_table",
            "verify_device_layout_and_identity", "backup_and_verify_preservation_regions",
            "resolve_repartition_policy", "execute_selected_operations_in_XML_order",
            "restore_and_verify_preserved_regions", "verify_written_images", "finalize_device",
        ],
        "finalization": {"vendor_requests_poweroff": bool(finish_poweroff), "automatic_reset_enabled": False},
        "execution": {"storage_writes_enabled": False, "full_flash_ready": False,
                      "blockers": list(dict.fromkeys(blockers))},
    }


def require_flash_ready(plan: dict) -> None:
    """Always reject unsupported execution before any transport is imported."""
    execution = plan.get("execution", {})
    if not execution.get("full_flash_ready") or not execution.get("storage_writes_enabled"):
        reasons = "; ".join(execution.get("blockers", ["no validated write executor"]))
        raise PlanError(f"device writes are disabled: {reasons}")
