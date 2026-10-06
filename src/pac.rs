//! Bounded, read-only BP_R2.0.1 PAC parsing with full 64-bit sizes and offsets.
//!
//! Format reference: bismoy-bot/PAC-Extractor at
//! 7d4e59b6a5ba86a7ea4e8c42d9c5f229037a6893 (MIT; see third_party).
//! Structural validation does not authenticate firmware or verify payload CRCs.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const HEADER_SIZE: usize = 2124;
pub const ENTRY_SIZE: usize = 2580;
pub const PAC_MAGIC: u32 = 0xfffa_fffa;
pub const MAX_ENTRIES: usize = 4096;
pub const MAX_READ_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacEntry {
    pub index: usize,
    pub id: String,
    pub name: String,
    pub size: u64,
    pub offset: u64,
    pub flag: u32,
    pub check_flag: u32,
    pub omit_flag: u32,
    pub addresses: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileSignature {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<Metadata> for FileSignature {
    fn from(meta: Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            size: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

#[derive(Debug)]
pub struct PacFile {
    pub path: PathBuf,
    pub product: String,
    pub version: String,
    pub firmware: String,
    pub alias: String,
    pub mode: u32,
    pub flash_type: u32,
    pub size: u64,
    pub crc1: u16,
    pub crc2: u16,
    pub entries: Vec<PacEntry>,
    signature: FileSignature,
    // Public metadata may be cloned for a plan, but must not redefine IO ranges.
    original_entries: Vec<PacEntry>,
}

fn open_regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("Cannot open PAC source: {}", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "PAC source must be a regular file"
    );
    Ok(file)
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed PAC field"),
    )
}

fn wide(bytes: &[u8], label: &str) -> Result<String> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16(&units).with_context(|| format!("Invalid UTF-16 in {label}"))
}

fn validate_filename(name: &str, index: usize) -> Result<()> {
    ensure!(
        name != "."
            && name != ".."
            && !name
                .chars()
                .any(|c| matches!(c, '/' | '\\' | ':') || c < '\u{20}' || c == '\u{7f}'),
        "Unsafe filename in entry {index}: {name:?}"
    );
    Ok(())
}

impl PacFile {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = fs::canonicalize(path.as_ref()).context("Cannot resolve PAC path")?;
        let mut file = open_regular(&path)?;
        let signature = FileSignature::from(file.metadata()?);
        let size = signature.size;
        ensure!(
            size >= HEADER_SIZE as u64,
            "File is too small for a PAC header"
        );
        let mut header = [0u8; HEADER_SIZE];
        file.read_exact(&mut header)
            .context("Unexpected EOF reading PAC header")?;
        let version = wide(&header[..44], "PAC version")?;
        ensure!(
            version == "BP_R2.0.1",
            "Unsupported PAC version: {version:?}"
        );
        ensure!(u32_at(&header, 2116) == PAC_MAGIC, "Invalid PAC magic");
        let declared_size = ((u32_at(&header, 44) as u64) << 32) | u32_at(&header, 48) as u64;
        ensure!(
            declared_size == size,
            "PAC size mismatch: header {declared_size}, file {size}"
        );
        let count = u32_at(&header, 1076) as usize;
        ensure!(
            (1..=MAX_ENTRIES).contains(&count),
            "Invalid PAC entry count: {count}"
        );
        let table_offset = u32_at(&header, 1080) as u64;
        ensure!(
            table_offset >= HEADER_SIZE as u64 && table_offset <= size,
            "PAC entry table lies outside the archive"
        );
        let table_length = count as u64 * ENTRY_SIZE as u64;
        ensure!(
            table_length <= size - table_offset,
            "PAC entry table extends beyond EOF"
        );
        let table_end = table_offset + table_length;
        file.seek(SeekFrom::Start(table_offset))?;
        let mut entries = Vec::with_capacity(count);
        for index in 0..count {
            let mut raw = [0u8; ENTRY_SIZE];
            file.read_exact(&mut raw)
                .with_context(|| format!("Unexpected EOF reading entry {index}"))?;
            ensure!(
                u32_at(&raw, 0) == ENTRY_SIZE as u32,
                "Unsupported entry size at index {index}"
            );
            let entry_size = ((u32_at(&raw, 1532) as u64) << 32) | u32_at(&raw, 1540) as u64;
            let offset = ((u32_at(&raw, 1536) as u64) << 32) | u32_at(&raw, 1552) as u64;
            let flag = u32_at(&raw, 1544);
            ensure!(flag <= 2, "Unsupported file flag {flag} at index {index}");
            ensure!(
                offset <= size && entry_size <= size - offset,
                "Entry {index} data range extends beyond EOF"
            );
            ensure!(
                entry_size == 0 || offset >= table_end,
                "Entry {index} data overlaps the PAC metadata"
            );
            ensure!(
                flag != 0 || entry_size == 0,
                "Operation-only entry {index} unexpectedly contains data"
            );
            let address_count = u32_at(&raw, 1560) as usize;
            ensure!(address_count <= 5, "Too many addresses at entry {index}");
            let name = wide(&raw[516..1028], &format!("entry {index} filename"))?;
            validate_filename(&name, index)?;
            ensure!(
                entry_size == 0 || !name.is_empty(),
                "Data entry {index} has no filename"
            );
            entries.push(PacEntry {
                index,
                id: wide(&raw[4..516], &format!("entry {index} ID"))?,
                name,
                size: entry_size,
                offset,
                flag,
                check_flag: u32_at(&raw, 1548),
                omit_flag: u32_at(&raw, 1556),
                addresses: (0..address_count)
                    .map(|i| u32_at(&raw, 1564 + 4 * i))
                    .collect(),
            });
        }
        let mut ranges: Vec<_> = entries.iter().filter(|e| e.size > 0).collect();
        ranges.sort_by_key(|e| e.offset);
        let mut end = table_end;
        for entry in ranges {
            ensure!(
                entry.offset >= end,
                "Overlapping payload range at entry {}",
                entry.index
            );
            end = entry.offset + entry.size; // Already bounded by archive size.
        }
        let pac = Self {
            path,
            product: wide(&header[52..564], "product")?,
            version,
            firmware: wide(&header[564..1076], "firmware version")?,
            alias: wide(&header[1104..1304], "product alias")?,
            mode: u32_at(&header, 1084),
            flash_type: u32_at(&header, 1088),
            size,
            crc1: u16::from_le_bytes(header[2120..2122].try_into().unwrap()),
            crc2: u16::from_le_bytes(header[2122..2124].try_into().unwrap()),
            original_entries: entries.clone(),
            entries,
            signature,
        };
        pac.check_open_file(&file)?;
        Ok(pac)
    }

    fn check_open_file(&self, file: &File) -> Result<()> {
        ensure!(
            FileSignature::from(file.metadata()?) == self.signature,
            "PAC source changed after it was parsed"
        );
        ensure!(
            FileSignature::from(fs::metadata(&self.path)?) == self.signature,
            "PAC source path changed after it was parsed"
        );
        Ok(())
    }

    pub fn ensure_unchanged(&self) -> Result<()> {
        self.check_open_file(&open_regular(&self.path)?)
    }

    fn check_entry(&self, entry: &PacEntry) -> Result<()> {
        ensure!(
            self.original_entries.get(entry.index) == Some(entry),
            "Entry does not match the original PAC metadata"
        );
        Ok(())
    }

    pub fn entries_for_id(&self, identifier: &str) -> Vec<&PacEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.id == identifier)
            .collect()
    }

    /// Copy the complete entry to a sink using bounded memory and exact reads.
    pub fn stream_entry<W: Write>(&self, entry: &PacEntry, output: &mut W) -> Result<u64> {
        self.check_entry(entry)?;
        let mut file = open_regular(&self.path)?;
        self.check_open_file(&file)?;
        file.seek(SeekFrom::Start(entry.offset))?;
        let mut buffer = vec![0u8; DEFAULT_CHUNK_BYTES];
        let mut remaining = entry.size;
        while remaining > 0 {
            let amount = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..amount])
                .with_context(|| format!("Unexpected EOF reading entry {}", entry.index))?;
            output
                .write_all(&buffer[..amount])
                .context("Cannot write PAC entry output")?;
            remaining -= amount as u64;
        }
        self.check_open_file(&file)?;
        Ok(entry.size)
    }

    pub fn read_range(&self, entry: &PacEntry, offset: u64, length: usize) -> Result<Vec<u8>> {
        self.check_entry(entry)?;
        ensure!(
            offset <= entry.size && length as u64 <= entry.size - offset,
            "Read range lies outside the PAC entry"
        );
        ensure!(
            length <= MAX_READ_BYTES,
            "Read range exceeds {MAX_READ_BYTES} bytes; use streaming"
        );
        let mut file = open_regular(&self.path)?;
        self.check_open_file(&file)?;
        file.seek(SeekFrom::Start(entry.offset + offset))?;
        let mut output = vec![0u8; length];
        file.read_exact(&mut output)
            .context("Unexpected EOF reading PAC range")?;
        self.check_open_file(&file)?;
        Ok(output)
    }

    pub fn read(&self, entry: &PacEntry) -> Result<Vec<u8>> {
        ensure!(
            entry.size <= MAX_READ_BYTES as u64,
            "Entry exceeds the in-memory read limit"
        );
        self.read_range(entry, 0, entry.size as usize)
    }

    pub fn hash_entry(&self, entry: &PacEntry) -> Result<String> {
        struct HashWriter(Sha256);
        impl Write for HashWriter {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0.update(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut sink = HashWriter(Sha256::new());
        self.stream_entry(entry, &mut sink)?;
        Ok(hex::encode(sink.0.finalize()))
    }

    /// Atomically publish a complete extraction. Existing files and symlinks
    /// are never overwritten. The caller supplies an exact output filename.
    pub fn extract(&self, entry: &PacEntry, outpath: &Path) -> Result<()> {
        self.check_entry(entry)?;
        ensure!(
            entry.flag != 0,
            "Entry {} is an operation, not a file",
            entry.index
        );
        let name = outpath
            .file_name()
            .context("Extraction target must be a filename")?;
        match fs::symlink_metadata(outpath) {
            Ok(_) => bail!("Extraction target already exists: {}", outpath.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        let parent = outpath
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let parent = fs::canonicalize(parent)?;
        let target = parent.join(name);
        let (mut file, temporary) = TemporaryOutput::new(&parent)?;
        self.stream_entry(entry, &mut file)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temporary.0, &target)
            .context("Cannot publish extracted file without overwriting")?;
        // The RAII guard unlinks the temporary name, retaining only the target.
        Ok(())
    }

    pub fn xml_text(&self) -> Result<String> {
        let entries: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.flag != 0 && e.name.to_ascii_lowercase().ends_with(".xml"))
            .collect();
        ensure!(
            entries.len() == 1,
            "Expected one embedded XML entry, found {}",
            entries.len()
        );
        let raw = self.read(entries[0])?;
        let text = if raw.starts_with(&[0xff, 0xfe]) {
            decode_utf16(&raw[2..], false)?
        } else if raw.starts_with(&[0xfe, 0xff]) {
            decode_utf16(&raw[2..], true)?
        } else if raw.starts_with(b"<\0") {
            decode_utf16(&raw, false)?
        } else if raw.starts_with(b"\0<") {
            decode_utf16(&raw, true)?
        } else {
            let raw = raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&raw);
            std::str::from_utf8(raw)
                .context("Invalid UTF-8 embedded XML")?
                .to_owned()
        };
        let text = text.trim_end_matches('\0').to_owned();
        let upper = text.to_ascii_uppercase();
        ensure!(
            !upper.contains("<!DOCTYPE") && !upper.contains("<!ENTITY"),
            "Embedded XML declarations for DTDs/entities are unsupported"
        );
        roxmltree::Document::parse(&text).context("Invalid embedded XML")?;
        Ok(text)
    }
}

fn decode_utf16(bytes: &[u8], big_endian: bool) -> Result<String> {
    ensure!(
        bytes.len() % 2 == 0,
        "Invalid odd-length UTF-16 embedded XML"
    );
    let units: Vec<_> = bytes
        .chunks_exact(2)
        .map(|b| {
            if big_endian {
                u16::from_be_bytes([b[0], b[1]])
            } else {
                u16::from_le_bytes([b[0], b[1]])
            }
        })
        .collect();
    String::from_utf16(&units).context("Invalid UTF-16 embedded XML")
}

struct TemporaryOutput(PathBuf);
impl TemporaryOutput {
    fn new(parent: &Path) -> Result<(File, Self)> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..128 {
            let index = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(".rgrotate-{}-{index}.tmp", std::process::id()));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => return Ok((file, Self(path))),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        bail!("Cannot create a unique extraction temporary file")
    }
}
impl Drop for TemporaryOutput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
