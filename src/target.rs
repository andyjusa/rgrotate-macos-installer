//! Offline target validation for the pinned RG Rotate GammaOS Next 1.4.1 Full PAC.
//!
//! No USB operations or writes occur here. Partition checks compare names and
//! reported MiB sizes, not raw GPT LBAs/CRCs. Source layouts and merge enum:
//! https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/android14-release/boot/1.1/default/boot_control/include/private/boot_control_definition.h
//! https://android.googlesource.com/platform/bootable/recovery/+/refs/heads/android14-release/bootloader_message/include/bootloader_message/bootloader_message.h
//! https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/android14-release/boot/1.1/types.hal

use crate::pac::{PacEntry, PacFile};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const MIB: u64 = 1024 * 1024;
pub const PAC_SIZE: u64 = 6674491170;
pub const PAC_SHA256: &str = "92b924a8baf2d83ec2f19d734daf5588a0a825596ee2ced285c98244b9d01208";

pub const EXPECTED_PARTITIONS: &[(&str, u64)] = &[
    ("prodnv", 10),
    ("miscdata", 1),
    ("misc", 1),
    ("trustos_a", 6),
    ("trustos_b", 6),
    ("sml_a", 1),
    ("sml_b", 1),
    ("uboot_a", 3),
    ("uboot_b", 3),
    ("uboot_log", 4),
    ("logo", 8),
    ("fbootlogo", 8),
    ("l_fixnv1_a", 2),
    ("l_fixnv2_a", 2),
    ("l_fixnv1_b", 2),
    ("l_fixnv2_b", 2),
    ("l_runtimenv1", 2),
    ("l_runtimenv2", 2),
    ("gnssmodem_a", 1),
    ("gnssmodem_b", 1),
    ("wcnmodem_a", 10),
    ("wcnmodem_b", 10),
    ("persist", 2),
    ("l_modem_a", 25),
    ("l_modem_b", 25),
    ("l_deltanv_a", 1),
    ("l_deltanv_b", 1),
    ("l_gdsp_a", 10),
    ("l_gdsp_b", 10),
    ("l_ldsp_a", 20),
    ("l_ldsp_b", 20),
    ("l_agdsp_a", 6),
    ("l_agdsp_b", 6),
    ("l_cdsp_a", 1),
    ("l_cdsp_b", 1),
    ("pm_sys_a", 1),
    ("pm_sys_b", 1),
    ("teecfg_a", 1),
    ("teecfg_b", 1),
    ("hypervsior_a", 10),
    ("hypervsior_b", 10),
    ("boot_a", 64),
    ("boot_b", 64),
    ("vendor_boot_a", 100),
    ("vendor_boot_b", 100),
    ("init_boot_a", 8),
    ("init_boot_b", 8),
    ("dtb_a", 8),
    ("dtb_b", 8),
    ("dtbo_a", 8),
    ("dtbo_b", 8),
    ("super", 5600),
    ("cache", 100),
    ("vbmeta_a", 1),
    ("vbmeta_b", 1),
    ("metadata", 16),
    ("sysdumpdb", 10),
    ("vbmeta_system_a", 1),
    ("vbmeta_system_b", 1),
    ("vbmeta_vendor_a", 1),
    ("vbmeta_vendor_b", 1),
    ("vbmeta_system_ext_a", 1),
    ("vbmeta_system_ext_b", 1),
    ("vbmeta_product_a", 1),
    ("vbmeta_product_b", 1),
    ("vbmeta_odm_a", 1),
    ("vbmeta_odm_b", 1),
    ("avbmeta_rs_a", 1),
    ("avbmeta_rs_b", 1),
    ("common_rs1_a", 8),
    ("common_rs1_b", 8),
    ("common_rs2_a", 16),
    ("common_rs2_b", 16),
    ("userdata", 4294967295),
];

#[derive(Clone, Debug)]
struct ImageSpec {
    partition: &'static str,
    identifier: &'static str,
    filename: &'static str,
    size: u64,
    sha256: &'static str,
}

const INSTALL_IMAGES: &[ImageSpec] = &[
    ImageSpec {
        partition: "super",
        identifier: "Super",
        filename: "full_super.img",
        size: 5872025600,
        sha256: "ddd80890ce8cf3700ac3b989a9f441e5dbc98ff80d94757b34f9675169b777e8",
    },
    ImageSpec {
        partition: "vbmeta_system_a",
        identifier: "VBMETA_SYSTEM",
        filename: "vbmeta_system_a.img",
        size: 1048576,
        sha256: "6083f4319806f24c81c65294d596bfb742f06fa2892b1b38e25feba1ce07d328",
    },
    ImageSpec {
        partition: "vbmeta_system_ext_a",
        identifier: "VBMETA_SYSTEM_EXT",
        filename: "vbmeta_system_ext_a.img",
        size: 1048576,
        sha256: "cda0144a8a5c36495fcfabfecce7644973a8df66992a1cef1b85eba8fa5d7231",
    },
    ImageSpec {
        partition: "vbmeta_vendor_a",
        identifier: "VBMETA_VENDOR",
        filename: "vbmeta_vendor_a.img",
        size: 1048576,
        sha256: "2c111f485e74e44675b2a0295262963f37910622d3ed39c76198a74dd907db3a",
    },
    ImageSpec {
        partition: "vbmeta_product_a",
        identifier: "VBMETA_PRODUCT",
        filename: "vbmeta_product_a.img",
        size: 1048576,
        sha256: "9a45bd0a61a62cb6790da3a3941d36fac2cafe3c5c1365671c9dc0f6e7c953a9",
    },
];

const BASELINE_IMAGES: &[ImageSpec] = &[
    ImageSpec {
        partition: "boot_a",
        identifier: "BOOT",
        filename: "boot_a.img",
        size: 67108864,
        sha256: "e3a43c0cd0b0a3b7ee3508d60b2cdca56121148f45f7ad3e6880781ad1a8621b",
    },
    ImageSpec {
        partition: "vendor_boot_a",
        identifier: "VENDORBOOT",
        filename: "vendor_boot_a.img",
        size: 104857600,
        sha256: "f76bcb7bf070177865554aaf5491279827eecd912891ffb9315733573365a2dd",
    },
    ImageSpec {
        partition: "init_boot_a",
        identifier: "INITBOOT",
        filename: "init_boot_a.img",
        size: 8388608,
        sha256: "2daeb1f36095b44b318410b3f4e8b5d989dcc7bb023d1426c492dab0a3053e74",
    },
    ImageSpec {
        partition: "dtbo_a",
        identifier: "DTBO",
        filename: "dtbo_a.img",
        size: 8388608,
        sha256: "a0c2cc17861b31fbc51fb7cd655404449689d54eb3ea2c01cc2a246fbda16f46",
    },
    ImageSpec {
        partition: "vbmeta_a",
        identifier: "VBMETA",
        filename: "vbmeta_a.img",
        size: 1048576,
        sha256: "4ed57d1968c1ab06cfa3cca750a310be3a04fe1b646701a75da9af4374f5b84e",
    },
];

const NV_PARTITIONS: &[&str] = &[
    "prodnv",
    "miscdata",
    "persist",
    "l_fixnv1_a",
    "l_fixnv2_a",
    "l_fixnv1_b",
    "l_fixnv2_b",
    "l_runtimenv1",
    "l_runtimenv2",
    "l_deltanv_a",
    "l_deltanv_b",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstallImage {
    pub entry: PacEntry,
    pub size: u64,
    pub sha256: String,
}

/// Proof of validation tied to an immutable borrow of the original PAC.
/// Private fields prevent constructing this token without successful validation.
pub struct ValidatedPac<'a> {
    pub pac: &'a PacFile,
    pub images: BTreeMap<String, InstallImage>,
    signature: FileSignature,
    baseline: Vec<ImageSpec>,
    reads: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileSignature {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileSignature {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }

    fn from_path(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("{}: cannot inspect validation input", basename(path)))?;
        ensure!(
            metadata.is_file(),
            "{}: expected a regular file",
            basename(path)
        );
        Ok(Self::from_metadata(&metadata))
    }
}

fn basename(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

struct CheckedFile {
    file: File,
    path: PathBuf,
    signature: FileSignature,
}

impl CheckedFile {
    fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("{}: cannot read validation input", basename(path)))?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file(),
            "{}: expected a regular file",
            basename(path)
        );
        let result = Self {
            file,
            path: path.to_owned(),
            signature: FileSignature::from_metadata(&metadata),
        };
        result.ensure_unchanged()?;
        Ok(result)
    }

    fn ensure_unchanged(&self) -> Result<()> {
        ensure!(
            self.signature == FileSignature::from_metadata(&self.file.metadata()?)
                && self.signature == FileSignature::from_path(&self.path)?,
            "{}: file changed during validation",
            basename(&self.path)
        );
        Ok(())
    }
}

fn hash_file(path: &Path, expected_size: Option<u64>) -> Result<String> {
    let mut source = CheckedFile::open(path)?;
    if let Some(expected) = expected_size {
        ensure!(
            source.signature.size == expected,
            "{}: length {}, expected {}",
            basename(path),
            source.signature.size,
            expected
        );
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0; MIB as usize];
    let mut count = 0u64;
    loop {
        let length = source.file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hash.update(&buffer[..length]);
        count = count
            .checked_add(length as u64)
            .context("File length overflow")?;
        ensure!(
            count <= source.signature.size,
            "{}: file grew during validation",
            basename(path)
        );
    }
    ensure!(
        count == source.signature.size,
        "{}: incomplete read",
        basename(path)
    );
    source.ensure_unchanged()?;
    Ok(hex::encode(hash.finalize()))
}

/// Hash every byte of a stable regular file, using bounded memory.
pub fn sha256_file(path: &Path) -> Result<String> {
    hash_file(path, None)
}

fn read_file(path: &Path, exact: Option<u64>, maximum: u64) -> Result<Vec<u8>> {
    let mut source = CheckedFile::open(path)?;
    let size = source.signature.size;
    ensure!(
        size <= maximum && exact.is_none_or(|expected| size == expected),
        "{}: invalid length {}",
        basename(path),
        size
    );
    let length = usize::try_from(size).context("Validation input exceeds address space")?;
    let mut data = vec![0; length];
    source
        .file
        .read_exact(&mut data)
        .context("Incomplete validation input")?;
    let mut extra = [0u8; 1];
    ensure!(
        source.file.read(&mut extra)? == 0,
        "{}: file grew during validation",
        basename(path)
    );
    source.ensure_unchanged()?;
    Ok(data)
}

pub fn required_before_reads() -> BTreeMap<String, u64> {
    let layout: BTreeMap<_, _> = EXPECTED_PARTITIONS.iter().copied().collect();
    BASELINE_IMAGES
        .iter()
        .map(|spec| spec.partition)
        .chain(std::iter::once("misc"))
        .chain(
            INSTALL_IMAGES
                .iter()
                .filter(|s| s.partition != "super")
                .map(|s| s.partition),
        )
        .chain(NV_PARTITIONS.iter().copied())
        .map(|name| (name.to_owned(), layout[name] * MIB))
        .collect()
}

fn image_entry<'a>(
    pac: &'a PacFile,
    xml: &roxmltree::Document<'_>,
    spec: &ImageSpec,
) -> Result<&'a PacEntry> {
    let entries = pac.entries_for_id(spec.identifier);
    ensure!(
        entries.len() == 1,
        "{}: exactly one PAC image is required",
        spec.partition
    );
    let entry = entries[0];
    ensure!(
        entry.name == spec.filename && entry.size == spec.size && entry.flag == 1,
        "{}: unexpected PAC image metadata",
        spec.partition
    );
    let nodes: Vec<_> = xml
        .descendants()
        .filter(|node| {
            node.has_tag_name("File")
                && node
                    .children()
                    .any(|child| child.has_tag_name("ID") && child.text() == Some(spec.identifier))
        })
        .collect();
    ensure!(
        nodes.len() == 1,
        "{}: missing or ambiguous XML mapping",
        spec.partition
    );
    let blocks: Vec<_> = nodes[0]
        .children()
        .filter(|node| node.has_tag_name("Block"))
        .collect();
    ensure!(
        blocks.len() == 1 && blocks[0].attribute("id") == Some(spec.partition),
        "{}: incorrect XML partition mapping",
        spec.partition
    );
    Ok(entry)
}

/// Authenticate the pinned archive and its five writable images before USB.
pub fn validate_pac(pac: &PacFile) -> Result<ValidatedPac<'_>> {
    validate_pac_with_specs(pac, PAC_SIZE, PAC_SHA256, INSTALL_IMAGES, BASELINE_IMAGES)
}

fn validate_pac_with_specs<'a>(
    pac: &'a PacFile,
    size: u64,
    hash: &str,
    installs: &[ImageSpec],
    baseline: &[ImageSpec],
) -> Result<ValidatedPac<'a>> {
    pac.ensure_unchanged()?;
    ensure!(
        pac.product == "ums512_1h10"
            && pac.firmware == "1.4.1"
            && pac.version == "BP_R2.0.1"
            && pac.size == size,
        "Only the pinned RG Rotate GammaOS Next 1.4.1 Full PAC is supported"
    );
    let signature = FileSignature::from_path(&pac.path)?;
    ensure!(
        hash_file(&pac.path, Some(size))? == hash,
        "PAC SHA-256 does not match the pinned official Full release"
    );
    let text = pac.xml_text()?;
    let xml = roxmltree::Document::parse(&text).context("Invalid PAC XML")?;
    let mut images = BTreeMap::new();
    for (spec, writable) in installs
        .iter()
        .map(|s| (s, true))
        .chain(baseline.iter().map(|s| (s, false)))
    {
        let entry = image_entry(pac, &xml, spec)?;
        ensure!(
            pac.hash_entry(entry)? == spec.sha256,
            "{}: official image SHA-256/length mismatch",
            spec.partition
        );
        if spec.partition == "super" {
            ensure!(
                pac.read_range(entry, 0, 4)? != [0x3a, 0xff, 0x26, 0xed],
                "Sparse super is unsupported; a verified RAW image is required"
            );
        }
        if writable {
            images.insert(
                spec.partition.to_owned(),
                InstallImage {
                    entry: entry.clone(),
                    size: spec.size,
                    sha256: spec.sha256.to_owned(),
                },
            );
        }
    }
    pac.ensure_unchanged()?;
    ensure!(
        signature == FileSignature::from_path(&pac.path)?,
        "PAC source changed during validation"
    );
    Ok(ValidatedPac {
        pac,
        images,
        signature,
        baseline: baseline.to_vec(),
        reads: required_before_reads(),
    })
}

fn validate_layout(data: &[u8]) -> Result<BTreeMap<String, u64>> {
    let text = std::str::from_utf8(data).context("Partition XML must be UTF-8")?;
    let upper = text.to_ascii_uppercase();
    ensure!(
        !upper.contains("<!DOCTYPE") && !upper.contains("<!ENTITY"),
        "Partition XML DTD/entity declarations are unsupported"
    );
    let xml = roxmltree::Document::parse(text).context("Malformed partition-list XML")?;
    let root = xml.root_element();
    ensure!(
        root.has_tag_name("Partitions") && root.attributes().len() == 0,
        "Unexpected partition-list XML root"
    );
    let mut actual = BTreeMap::new();
    for node in root.children().filter(|node| node.is_element()) {
        ensure!(
            node.has_tag_name("Partition")
                && node.attributes().len() == 2
                && node.attribute("id").is_some()
                && node.attribute("size").is_some()
                && !node.children().any(|node| node.is_element()),
            "Unexpected partition-list XML element"
        );
        let name = node.attribute("id").context("Missing partition ID")?;
        let size = node.attribute("size").context("Missing partition size")?;
        let size = if size.starts_with("0x") || size.starts_with("0X") {
            u64::from_str_radix(&size[2..], 16)
        } else {
            size.parse::<u64>()
        }
        .with_context(|| format!("Invalid partition size for {name}"))?;
        ensure!(
            actual.insert(name.to_owned(), size).is_none(),
            "Duplicate partition in device layout: {name}"
        );
    }
    let expected: BTreeMap<_, _> = EXPECTED_PARTITIONS
        .iter()
        .map(|(n, s)| ((*n).to_owned(), *s))
        .collect();
    if actual != expected {
        let missing: Vec<_> = expected
            .keys()
            .filter(|name| !actual.contains_key(*name))
            .collect();
        let extra: Vec<_> = actual
            .keys()
            .filter(|name| !expected.contains_key(*name))
            .collect();
        let changed: Vec<_> = actual
            .keys()
            .filter(|name| {
                expected
                    .get(*name)
                    .is_some_and(|s| Some(s) != actual.get(*name))
            })
            .collect();
        bail!(
            "Incompatible partition layout: missing={missing:?}, extra={extra:?}, size={changed:?}"
        );
    }
    Ok(actual)
}

fn le_u32(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

fn validate_misc(data: &[u8]) -> Result<Value> {
    ensure!(
        data.len() == MIB as usize,
        "misc must contain the complete 1 MiB partition"
    );
    ensure!(
        data[..32].iter().all(|byte| *byte == 0),
        "BCB already contains a pending bootloader command"
    );
    ensure!(
        data[832..864].iter().all(|byte| *byte == 0),
        "BCB has a pending multistage recovery operation"
    );
    let control = &data[2048..2080];
    ensure!(
        &control[..4] == b"_a\0\0",
        "The active boot-control slot must be A"
    );
    ensure!(
        le_u32(&control[4..8]) == 0x42414342 && control[8] == 1,
        "Unrecognized boot-control magic or version"
    );
    ensure!(
        control[9] & 7 == 2,
        "Exactly two boot-control slots are required"
    );
    ensure!(
        le_u32(&control[28..32]) == crc32fast::hash(&control[..28]),
        "Boot-control CRC32 is invalid"
    );
    // Packed bitfields: slots=bits72..74, recovery=75..77, merge=78..80.
    let merge_status = (control[9] >> 6) | ((control[10] & 1) << 2);
    ensure!(
        merge_status == 0,
        "Boot-control reports a pending snapshot merge"
    );
    let priority_a = control[12] & 15;
    let priority_b = control[14] & 15;
    ensure!(
        priority_a != 0 && control[12] & 0x80 != 0 && control[13] & 1 == 0,
        "Slot A must be successful, bootable, and free of verity corruption"
    );
    ensure!(
        priority_a > priority_b,
        "Slot A must have strictly greater boot priority than B"
    );
    let virtual_ab = &data[32768..32832];
    ensure!(
        virtual_ab.iter().any(|byte| *byte != 0),
        "Virtual A/B status is uninitialized; absence of snapshots is unverified"
    );
    ensure!(
        virtual_ab[0] == 2 && le_u32(&virtual_ab[1..5]) == 0x56740ab0,
        "Unrecognized Virtual A/B status version or magic"
    );
    ensure!(
        virtual_ab[5] == 0,
        "Virtual A/B snapshot status must be NONE (0)"
    );
    ensure!(virtual_ab[6] <= 1, "Virtual A/B source slot is invalid");
    Ok(
        json!({"active_slot":"a", "slot_a_successful":true, "bootctrl_crc32_valid":true,
              "snapshot_status":"none", "snapshot_source_slot":virtual_ab[6]}),
    )
}

/// Validate saved device reads without repeating a multi-GiB PAC hash in FDL.
pub fn validate_preflight(validated: &ValidatedPac<'_>, out_dir: &Path) -> Result<Value> {
    validated.pac.ensure_unchanged()?;
    ensure!(
        validated.signature == FileSignature::from_path(&validated.pac.path)?,
        "PAC source changed after validation"
    );
    let layout = validate_layout(&read_file(&out_dir.join("partitions.xml"), None, MIB)?)?;
    let mut before = serde_json::Map::new();
    let mut misc = Value::Null;
    for (name, size) in &validated.reads {
        let path = out_dir.join("before").join(format!("{name}.bin"));
        let digest = if name == "misc" {
            let data = read_file(&path, Some(MIB), MIB)?;
            misc = validate_misc(&data)?;
            hex::encode(Sha256::digest(&data))
        } else {
            hash_file(&path, Some(*size))?
        };
        if let Some(spec) = validated
            .baseline
            .iter()
            .find(|spec| spec.partition == name)
        {
            ensure!(
                digest == spec.sha256,
                "{name}: existing boot image differs from the official PAC"
            );
        }
        before.insert(name.clone(), json!({"size":size,"sha256":digest}));
    }
    ensure!(!misc.is_null(), "Missing misc preflight requirement");
    // Proves that the >4 GiB read path completed, not that Lite's tail is Full.
    before.insert(
        "super-tail".to_owned(),
        json!({"size":MIB,
        "sha256":hash_file(&out_dir.join("before/super-tail.bin"), Some(MIB))?}),
    );
    validated.pac.ensure_unchanged()?;
    ensure!(
        validated.signature == FileSignature::from_path(&validated.pac.path)?,
        "PAC source changed during preflight"
    );
    Ok(
        json!({"partition_layout":layout, "before":before, "misc":misc,
        "pac_sha256":PAC_SHA256,
        "limitations":["Partition list validates names and reported MiB sizes, not raw GPT LBAs/CRCs.",
            "Snapshot check validates the boot-control and misc Virtual A/B records; metadata files are not inspected."]}),
    )
}

/// Build a wipe request, preserving every byte outside command and recovery.
pub fn patch_misc(data: &[u8]) -> Result<Vec<u8>> {
    validate_misc(data)?;
    let mut result = data.to_vec();
    result[..32].fill(0);
    result[..13].copy_from_slice(b"boot-recovery");
    result[64..832].fill(0);
    let recovery = b"recovery\n--wipe_data\n";
    result[64..64 + recovery.len()].copy_from_slice(recovery);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn good_misc() -> Vec<u8> {
        let mut data = vec![0; MIB as usize];
        data[32..45].copy_from_slice(b"legacy-status");
        data[1100..1106].copy_from_slice(b"vendor");
        data[17000..17004].copy_from_slice(b"wipe");
        data[800000..800004].copy_from_slice(b"tail");
        data[2048..2080].copy_from_slice(
            &hex::decode("5f61000042434142010200009f008e000000000000000000000000008532b0a3")
                .unwrap(),
        );
        data[32768] = 2;
        data[32769..32773].copy_from_slice(&0x56740ab0u32.to_le_bytes());
        data
    }

    fn update_control(data: &mut [u8], offset: usize, value: u8) {
        data[2048 + offset] = value;
        let crc = crc32fast::hash(&data[2048..2076]);
        data[2076..2080].copy_from_slice(&crc.to_le_bytes());
    }

    fn layout_xml() -> String {
        let mut xml = String::from("<Partitions>");
        for (name, size) in EXPECTED_PARTITIONS {
            let size = if *name == "userdata" {
                "0xffffffff".to_owned()
            } else {
                size.to_string()
            };
            xml.push_str(&format!("<Partition id=\"{name}\" size=\"{size}\"/>"));
        }
        xml.push_str("</Partitions>");
        xml
    }

    #[test]
    fn patch_preserves_every_byte_outside_two_fields() {
        let original = good_misc();
        let result = patch_misc(&original).unwrap();
        assert_eq!(result.len(), MIB as usize);
        assert_eq!(&result[..13], b"boot-recovery");
        assert!(result[13..32].iter().all(|b| *b == 0));
        assert_eq!(&result[64..85], b"recovery\n--wipe_data\n");
        assert!(result[85..832].iter().all(|b| *b == 0));
        assert_eq!(result[32..64], original[32..64]);
        assert_eq!(result[832..], original[832..]);
        assert_eq!(original, good_misc());
    }

    #[test]
    fn successful_active_a() {
        let state = validate_misc(&good_misc()).unwrap();
        assert_eq!(state["active_slot"], "a");
        assert_eq!(state["snapshot_status"], "none");
    }

    #[test]
    fn short_and_oversized_misc_rejected_without_panicking() {
        for length in [0, 31, 2048, 32768, MIB as usize - 1, MIB as usize + 1] {
            assert!(patch_misc(&vec![0; length]).is_err());
        }
    }

    #[test]
    fn pending_command_and_multistage_recovery_rejected() {
        for offset in [0, 31, 832, 863] {
            let mut data = good_misc();
            data[offset] = 1;
            assert!(patch_misc(&data).is_err());
        }
    }

    #[test]
    fn corrupt_crc_rejected() {
        let mut data = good_misc();
        data[2076] ^= 1;
        assert!(patch_misc(&data).unwrap_err().to_string().contains("CRC32"));
    }

    #[test]
    fn incompatible_boot_control_rejected_with_valid_crc() {
        for (offset, value) in [
            (1, b'b'),
            (4, 0),
            (8, 2),
            (9, 1),
            (12, 0x1f),
            (12, 0x80),
            (13, 1),
            (14, 0x8f),
        ] {
            let mut data = good_misc();
            update_control(&mut data, offset, value);
            assert!(patch_misc(&data).is_err(), "offset {offset}, value {value}");
        }
    }

    #[test]
    fn packed_merge_status_crossing_byte_boundary_rejected() {
        for status in 1u8..=7 {
            let mut data = good_misc();
            update_control(&mut data, 9, 2 | ((status & 3) << 6));
            update_control(&mut data, 10, status >> 2);
            let error = patch_misc(&data).unwrap_err().to_string();
            assert!(
                error.contains("pending snapshot merge"),
                "status {status}: {error}"
            );
        }
    }

    #[test]
    fn every_nonzero_virtual_ab_status_rejected() {
        for status in 1u8..=255 {
            let mut data = good_misc();
            data[32773] = status;
            assert!(patch_misc(&data).unwrap_err().to_string().contains("NONE"));
        }
    }

    #[test]
    fn unknown_and_uninitialized_virtual_ab_rejected() {
        for (offset, value) in [(32768, 1), (32769, 0), (32774, 2)] {
            let mut data = good_misc();
            data[offset] = value;
            assert!(patch_misc(&data).is_err());
        }
        let mut data = good_misc();
        data[32768..32832].fill(0);
        assert!(
            patch_misc(&data)
                .unwrap_err()
                .to_string()
                .contains("uninitialized")
        );
    }

    #[test]
    fn all_74_names_sizes_and_userdata_sentinel() {
        let actual = validate_layout(layout_xml().as_bytes()).unwrap();
        assert_eq!(actual.len(), 74);
        assert_eq!(actual["super"], 5600);
        assert_eq!(actual["userdata"], 0xffffffff);
        assert!(PAC_SIZE > u32::MAX as u64);
        assert!(INSTALL_IMAGES[0].size > u32::MAX as u64);
        assert_eq!(required_before_reads().len(), 21);
        assert!(!required_before_reads().contains_key("super-tail"));
    }

    #[test]
    fn missing_extra_changed_duplicate_partition_rejected() {
        let good = layout_xml();
        let cases = [
            good.replace("<Partition id=\"misc\" size=\"1\"/>", ""),
            good.replace(
                "</Partitions>",
                "<Partition id=\"unknown\" size=\"1\"/></Partitions>",
            ),
            good.replace("id=\"super\" size=\"5600\"", "id=\"super\" size=\"4096\""),
            good.replace(
                "</Partitions>",
                "<Partition id=\"misc\" size=\"1\"/></Partitions>",
            ),
        ];
        for xml in cases {
            assert!(validate_layout(xml.as_bytes()).is_err());
        }
    }

    #[test]
    fn malformed_nested_dtd_xml_rejected() {
        for xml in [
            "<",
            "<Other/>",
            "<Partitions><Unknown/></Partitions>",
            "<!DOCTYPE Partitions [<!ENTITY x 'x'>]><Partitions/>",
            "<Partitions><Partition id='misc' size='1'><Child/></Partition></Partitions>",
        ] {
            assert!(validate_layout(xml.as_bytes()).is_err());
        }
    }

    #[test]
    fn negative_noninteger_overflow_size_rejected() {
        for value in ["1.0", "-1", "garbage", "18446744073709551616"] {
            let xml = layout_xml().replace(
                "id=\"misc\" size=\"1\"",
                &format!("id=\"misc\" size=\"{value}\""),
            );
            assert!(validate_layout(xml.as_bytes()).is_err());
        }
    }

    #[test]
    fn hash_includes_full_tail() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("image");
        let mut data = vec![b'a'; MIB as usize + 31];
        data.extend_from_slice(b"tail");
        fs::write(&path, &data).unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            hex::encode(Sha256::digest(&data))
        );
    }

    #[test]
    fn missing_directory_symlink_rejected() {
        let dir = TempDir::new().unwrap();
        let link = dir.path().join("link");
        symlink(dir.path(), &link).unwrap();
        for path in [dir.path().to_owned(), dir.path().join("missing"), link] {
            assert!(sha256_file(&path).is_err());
        }
    }

    #[test]
    fn source_mutation_while_open_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("image");
        fs::write(&path, b"original").unwrap();
        let source = CheckedFile::open(&path).unwrap();
        fs::write(&path, b"different").unwrap();
        assert!(source.ensure_unchanged().is_err());
    }

    #[test]
    fn source_replaced_with_same_size_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("image");
        let replacement = dir.path().join("replacement");
        fs::write(&path, b"original").unwrap();
        fs::write(&replacement, b"original").unwrap();
        let source = CheckedFile::open(&path).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(source.ensure_unchanged().is_err());
    }

    fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
        buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_wide(buffer: &mut [u8], offset: usize, value: &str) {
        for (index, unit) in value.encode_utf16().enumerate() {
            buffer[offset + index * 2..offset + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }

    struct Fixture {
        dir: TempDir,
        pac: PacFile,
        installs: Vec<ImageSpec>,
        baseline: Vec<ImageSpec>,
        payloads: BTreeMap<String, Vec<u8>>,
        archive_hash: String,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("fixture.pac");
            let mut payloads = BTreeMap::new();
            let mut specs = Vec::new();
            let mut xml = String::from("<BMAConfig>");
            for original in INSTALL_IMAGES.iter().chain(BASELINE_IMAGES.iter()) {
                let payload = format!("{}:payload", original.partition).into_bytes();
                let digest = hex::encode(Sha256::digest(&payload));
                let mut spec = original.clone();
                spec.size = payload.len() as u64;
                // The small number of test-only SHA strings have process lifetime.
                spec.sha256 = Box::leak(digest.into_boxed_str());
                specs.push(spec);
                payloads.insert(original.partition.to_owned(), payload);
                xml.push_str(&format!(
                    "<File><ID>{}</ID><Block id=\"{}\"/></File>",
                    original.identifier, original.partition
                ));
            }
            xml.push_str("</BMAConfig>");
            let mut entries: Vec<_> = specs
                .iter()
                .map(|s| (s.identifier, s.filename, payloads[s.partition].clone()))
                .collect();
            entries.push(("XML", "configuration.xml", xml.into_bytes()));
            let table_end = 2124 + 2580 * entries.len();
            let total = table_end
                + entries
                    .iter()
                    .map(|(_, _, bytes)| bytes.len())
                    .sum::<usize>();
            let mut archive = vec![0; total];
            put_wide(&mut archive, 0, "BP_R2.0.1");
            put_u32(&mut archive, 48, total as u32);
            put_wide(&mut archive, 52, "ums512_1h10");
            put_wide(&mut archive, 564, "1.4.1");
            put_u32(&mut archive, 1076, entries.len() as u32);
            put_u32(&mut archive, 1080, 2124);
            put_u32(&mut archive, 2116, 0xfffafffa);
            let mut offset = table_end;
            for (index, (id, name, payload)) in entries.iter().enumerate() {
                let start = 2124 + index * 2580;
                let entry = &mut archive[start..start + 2580];
                put_u32(entry, 0, 2580);
                put_wide(entry, 4, id);
                put_wide(entry, 516, name);
                put_u32(entry, 1540, payload.len() as u32);
                put_u32(entry, 1544, 1);
                put_u32(entry, 1548, 1);
                put_u32(entry, 1552, offset as u32);
                archive[offset..offset + payload.len()].copy_from_slice(payload);
                offset += payload.len();
            }
            fs::write(&path, &archive).unwrap();
            let archive_hash = hex::encode(Sha256::digest(&archive));
            let pac = PacFile::new(&path).unwrap();
            let before = dir.path().join("before");
            fs::create_dir(&before).unwrap();
            for name in required_before_reads().keys() {
                let data = if name == "misc" {
                    good_misc()
                } else {
                    payloads.get(name).cloned().unwrap_or(vec![0; 16])
                };
                fs::write(before.join(format!("{name}.bin")), data).unwrap();
            }
            fs::write(before.join("super-tail.bin"), vec![0; MIB as usize]).unwrap();
            fs::write(dir.path().join("partitions.xml"), layout_xml()).unwrap();
            let baseline = specs.split_off(INSTALL_IMAGES.len());
            Self {
                dir,
                pac,
                installs: specs,
                baseline,
                payloads,
                archive_hash,
            }
        }

        fn validate(&self) -> Result<ValidatedPac<'_>> {
            let mut validated = validate_pac_with_specs(
                &self.pac,
                self.pac.size,
                &self.archive_hash,
                &self.installs,
                &self.baseline,
            )?;
            for (name, size) in &mut validated.reads {
                *size = if name == "misc" {
                    MIB
                } else {
                    self.payloads
                        .get(name)
                        .map_or(16, |bytes| bytes.len() as u64)
                };
            }
            Ok(validated)
        }
    }

    #[test]
    fn validated_images_and_json_preflight() {
        let fixture = Fixture::new();
        let validated = fixture.validate().unwrap();
        assert_eq!(validated.images.len(), 5);
        for spec in &fixture.installs {
            let image = &validated.images[spec.partition];
            assert_eq!(image.sha256, spec.sha256);
            assert_eq!(image.size, spec.size);
        }
        let state = validate_preflight(&validated, fixture.dir.path()).unwrap();
        assert_eq!(state["before"]["super-tail"]["size"], MIB);
        assert_eq!(state["before"].as_object().unwrap().len(), 22);
        serde_json::to_string(&state).unwrap();
    }

    #[test]
    fn public_validator_cannot_accept_fixture_as_pinned_release() {
        let fixture = Fixture::new();
        assert!(validate_pac(&fixture.pac).is_err());
    }

    #[test]
    fn wrong_archive_hash_rejected() {
        let fixture = Fixture::new();
        let result = validate_pac_with_specs(
            &fixture.pac,
            fixture.pac.size,
            &"0".repeat(64),
            &fixture.installs,
            &fixture.baseline,
        );
        assert!(result.err().unwrap().to_string().contains("PAC SHA-256"));
    }

    #[test]
    fn wrong_product_metadata_rejected() {
        let mut fixture = Fixture::new();
        fixture.pac.product = "different".to_owned();
        assert!(
            fixture
                .validate()
                .err()
                .unwrap()
                .to_string()
                .contains("Only the pinned")
        );
    }

    #[test]
    fn changed_archive_after_validation_rejected() {
        let fixture = Fixture::new();
        let validated = fixture.validate().unwrap();
        let mut source = OpenOptions::new()
            .write(true)
            .open(&fixture.pac.path)
            .unwrap();
        source.seek(SeekFrom::End(-1)).unwrap();
        source.write_all(b"x").unwrap();
        source.sync_all().unwrap();
        assert!(validate_preflight(&validated, fixture.dir.path()).is_err());
    }

    #[test]
    fn wrong_image_hash_rejected() {
        let mut fixture = Fixture::new();
        fixture.installs[0].sha256 = "wrong";
        assert!(
            fixture
                .validate()
                .err()
                .unwrap()
                .to_string()
                .contains("image SHA-256")
        );
    }

    #[test]
    fn duplicate_image_entry_rejected() {
        let mut fixture = Fixture::new();
        let entry = fixture.pac.entries[0].clone();
        fixture.pac.entries.push(entry);
        assert!(fixture.validate().is_err());
    }

    #[test]
    fn renamed_image_metadata_rejected() {
        let mut fixture = Fixture::new();
        fixture.installs[0].filename = "userdata.img";
        assert!(
            fixture
                .validate()
                .err()
                .unwrap()
                .to_string()
                .contains("metadata")
        );
    }

    #[test]
    fn wrong_xml_partition_mapping_rejected() {
        let fixture = Fixture::new();
        let text = fixture
            .pac
            .xml_text()
            .unwrap()
            .replace("id=\"super\"", "id=\"userdata\"");
        let xml = roxmltree::Document::parse(&text).unwrap();
        assert!(
            image_entry(&fixture.pac, &xml, &fixture.installs[0])
                .unwrap_err()
                .to_string()
                .contains("incorrect XML")
        );
    }

    #[test]
    fn missing_nv_backup_rejected() {
        let fixture = Fixture::new();
        let validated = fixture.validate().unwrap();
        fs::remove_file(fixture.dir.path().join("before/prodnv.bin")).unwrap();
        assert!(
            validate_preflight(&validated, fixture.dir.path())
                .unwrap_err()
                .to_string()
                .contains("prodnv")
        );
    }

    #[test]
    fn short_nv_backup_rejected() {
        let fixture = Fixture::new();
        let validated = fixture.validate().unwrap();
        fs::write(fixture.dir.path().join("before/persist.bin"), []).unwrap();
        assert!(
            validate_preflight(&validated, fixture.dir.path())
                .unwrap_err()
                .to_string()
                .contains("length")
        );
    }

    #[test]
    fn existing_boot_mismatch_rejected() {
        let fixture = Fixture::new();
        let validated = fixture.validate().unwrap();
        let size = fixture.payloads["boot_a"].len();
        fs::write(
            fixture.dir.path().join("before/boot_a.bin"),
            vec![b'x'; size],
        )
        .unwrap();
        assert!(
            validate_preflight(&validated, fixture.dir.path())
                .unwrap_err()
                .to_string()
                .contains("differs")
        );
    }

    #[test]
    fn missing_or_short_super_tail_rejected() {
        let fixture = Fixture::new();
        let validated = fixture.validate().unwrap();
        let path = fixture.dir.path().join("before/super-tail.bin");
        fs::remove_file(&path).unwrap();
        assert!(
            validate_preflight(&validated, fixture.dir.path())
                .unwrap_err()
                .to_string()
                .contains("super-tail")
        );
        fs::write(path, b"tail").unwrap();
        assert!(
            validate_preflight(&validated, fixture.dir.path())
                .unwrap_err()
                .to_string()
                .contains("length")
        );
    }
}
