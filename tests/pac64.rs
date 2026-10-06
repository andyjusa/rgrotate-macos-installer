#[path = "pac_support/mod.rs"]
mod support;
use rgrotate::pac::{MAX_READ_BYTES, PacFile};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::PathBuf;
use support::{ENTRY, FixtureEntry, HEADER, patch, write_fixture};
use tempfile::tempdir;

#[test]
fn large_offsets_extract_exact_bytes_without_allocating_holes() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("firmware.pac");
    let payload = b"payload beyond 32-bit offsets\0\xff";
    let mut entry = FixtureEntry::file("FDL2", "fdl2.bin", payload);
    entry.offset = Some((1u64 << 32) + 8192);
    write_fixture(&source, &[entry]);
    let pac = PacFile::new(&source).unwrap();
    let entry = &pac.entries[0];
    assert_eq!(entry.offset, (1u64 << 32) + 8192);
    assert_eq!(pac.size, entry.offset + payload.len() as u64);
    assert_eq!(pac.read(entry).unwrap(), payload);
    let target = dir.path().join("selected/fdl2.bin");
    pac.extract(entry, &target).unwrap();
    assert_eq!(fs::read(target).unwrap(), payload);
    assert!(fs::metadata(source).unwrap().blocks() * 512 < 1024 * 1024);
}

#[test]
fn large_sizes_stream_completely_and_tail_ranges_do_not_wrap() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("firmware.pac");
    let size = (1u64 << 32) + 31;
    let mut entry = FixtureEntry::file("Super", "super.img", b"BEGIN");
    entry.size = size;
    entry.fragments.push((size - 4, b"TAIL".to_vec()));
    write_fixture(&source, &[entry]);
    let pac = PacFile::new(&source).unwrap();
    let entry = &pac.entries[0];
    assert_eq!(entry.size, size);
    assert_eq!(pac.read_range(entry, size - 4, 4).unwrap(), b"TAIL");
    assert!(pac.read(entry).is_err());
    struct Count {
        bytes: u64,
        tail: Vec<u8>,
    }
    impl Write for Count {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.bytes += data.len() as u64;
            self.tail = data[data.len().saturating_sub(4)..].to_vec();
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Count {
        bytes: 0,
        tail: Vec::new(),
    };
    assert_eq!(pac.stream_entry(entry, &mut sink).unwrap(), size);
    assert_eq!(sink.bytes, size);
    assert_eq!(sink.tail, b"TAIL");
    assert!(fs::metadata(source).unwrap().blocks() * 512 < 1024 * 1024);
}

#[test]
fn xml_above_four_gib_decodes_unicode_and_all_supported_encodings() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("firmware.pac");
    let xml = "<BMAConfig><Product name=\"한글🎮\"/></BMAConfig>\0";
    let mut variants = vec![xml.as_bytes().to_vec()];
    variants.push([b"\xef\xbb\xbf".to_vec(), xml.as_bytes().to_vec()].concat());
    let little: Vec<_> = xml.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let big: Vec<_> = xml.encode_utf16().flat_map(u16::to_be_bytes).collect();
    variants.push(little.clone());
    variants.push(big.clone());
    variants.push([vec![0xff, 0xfe], little].concat());
    variants.push([vec![0xfe, 0xff], big].concat());
    for raw in variants {
        let mut entry = FixtureEntry::file("", "config.XML", &raw);
        entry.flag = 2;
        entry.offset = Some((1u64 << 32) + 4096);
        write_fixture(&source, &[entry]);
        assert_eq!(
            PacFile::new(&source).unwrap().xml_text().unwrap(),
            xml.trim_end_matches('\0')
        );
    }
}

#[test]
fn duplicate_ids_and_names_remain_distinct_and_clones_are_valid() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("firmware.pac");
    write_fixture(
        &source,
        &[
            FixtureEntry::file("UBOOTLoader", "same.img", b"a"),
            FixtureEntry::file("UBOOTLoader", "same.img", b"b"),
        ],
    );
    let pac = PacFile::new(&source).unwrap();
    assert_eq!(pac.entries_for_id("UBOOTLoader").len(), 2);
    assert_eq!(pac.read(&pac.entries[0].clone()).unwrap(), b"a");
    assert_eq!(pac.read(&pac.entries[1]).unwrap(), b"b");
    assert_ne!(pac.entries[0].offset, pac.entries[1].offset);
}

#[test]
fn rejects_bad_versions_header_counts_and_tables() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("firmware.pac");
    let entry = FixtureEntry::file("FDL", "image.bin", b"small");
    for version in ["BP_R1.0.0", "BP_R2.0.2", "unknown"] {
        write_fixture(&source, std::slice::from_ref(&entry));
        let mut bytes = [0u8; 44];
        support::put_wide(&mut bytes, 0, 44, version);
        patch(&source, 0, &bytes);
        assert!(PacFile::new(&source).is_err());
    }
    for (offset, value) in [
        (2116, 0),
        (44, 1),
        (1076, 0),
        (1076, u32::MAX),
        (1076, 2),
        (1080, HEADER as u32 - 1),
        (1080, u32::MAX),
    ] {
        write_fixture(&source, std::slice::from_ref(&entry));
        patch(&source, offset, &value.to_le_bytes());
        assert!(
            PacFile::new(&source).is_err(),
            "offset {offset}, value {value}"
        );
    }
    fs::write(&source, vec![0; HEADER - 1]).unwrap();
    assert!(PacFile::new(&source).is_err());
}

#[test]
fn rejects_entry_overflow_metadata_overlap_flags_and_bad_addresses() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("firmware.pac");
    for (position, value) in [
        (0, ENTRY as u32 - 4),
        (1532, u32::MAX),
        (1536, u32::MAX),
        (1540, u32::MAX),
        (1552, 0),
        (1544, 3),
        (1544, 0),
        (1560, 6),
    ] {
        write_fixture(
            &source,
            &[FixtureEntry::file("image", "image.bin", b"small")],
        );
        patch(&source, HEADER as u64 + position, &value.to_le_bytes());
        assert!(PacFile::new(&source).is_err(), "position {position}");
    }
    let a = FixtureEntry::file("a", "a.bin", b"AAAA");
    let mut b = FixtureEntry::file("b", "b.bin", b"BBBB");
    b.offset = Some((HEADER + ENTRY * 2) as u64 + 1);
    write_fixture(&source, &[a, b]);
    assert!(PacFile::new(&source).is_err());
}

#[test]
fn rejects_traversal_including_windows_paths_and_controls() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("firmware.pac");
    for name in [
        "../escape",
        "a/../escape",
        "/absolute",
        ".",
        "..",
        "C:\\escape",
        "a\\escape",
        "x\ny",
    ] {
        write_fixture(&source, &[FixtureEntry::file("image", name, b"a")]);
        assert!(PacFile::new(&source).is_err(), "{name}");
    }
}

#[test]
fn rejects_existing_extraction_outputs_and_dangling_symlinks() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("firmware.pac");
    write_fixture(
        &source,
        &[FixtureEntry::file("image", "image.bin", b"payload")],
    );
    let pac = PacFile::new(&source).unwrap();
    let victim = dir.path().join("victim");
    fs::write(&victim, b"KEEP").unwrap();
    let link = dir.path().join("link");
    symlink(&victim, &link).unwrap();
    let dangling = dir.path().join("dangling");
    symlink(dir.path().join("absent"), &dangling).unwrap();
    for output in [&victim, &link, &dangling, &source] {
        assert!(pac.extract(&pac.entries[0], output).is_err());
    }
    assert_eq!(fs::read(victim).unwrap(), b"KEEP");
    assert!(fs::symlink_metadata(link).unwrap().is_symlink());
}

#[test]
fn detects_changed_or_replaced_sources_without_leaving_partial_output() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("firmware.pac");
    for replace in [false, true] {
        write_fixture(
            &source,
            &[FixtureEntry::file("image", "image.bin", b"payload")],
        );
        let pac = PacFile::new(&source).unwrap();
        if replace {
            let replacement = dir.path().join("replacement");
            fs::copy(&source, &replacement).unwrap();
            fs::rename(replacement, &source).unwrap();
        } else {
            File::options()
                .write(true)
                .open(&source)
                .unwrap()
                .set_len(pac.size - 1)
                .unwrap();
        }
        let output = dir.path().join("output");
        assert!(pac.ensure_unchanged().is_err());
        assert!(pac.extract(&pac.entries[0], &output).is_err());
        assert!(!output.exists());
        assert!(!fs::read_dir(dir.path()).unwrap().any(|p| {
            p.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".rgrotate-")
        }));
    }
}

#[test]
fn fifo_is_rejected_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempdir().unwrap();
    let path = dir.path().join("fifo");
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    assert!(
        PacFile::new(path)
            .unwrap_err()
            .to_string()
            .contains("regular file")
    );
}

#[test]
fn streaming_detects_midstream_eof_and_output_failures() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("firmware.pac");
    let mut entry = FixtureEntry::file("image", "image.bin", b"payload");
    entry.size = 3 * 1024 * 1024;
    write_fixture(&path, &[entry]);
    let pac = PacFile::new(&path).unwrap();
    struct Truncate(PathBuf);
    impl Write for Truncate {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            File::options().write(true).open(&self.0)?.set_len(0)?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert!(
        pac.stream_entry(&pac.entries[0], &mut Truncate(path.clone()))
            .unwrap_err()
            .to_string()
            .contains("EOF")
    );
    write_fixture(
        &path,
        &[FixtureEntry::file("image", "image.bin", b"payload")],
    );
    let pac = PacFile::new(&path).unwrap();
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("disk full"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert!(pac.stream_entry(&pac.entries[0], &mut Broken).is_err());
}

#[test]
fn invalid_ranges_changed_entry_metadata_and_operations_are_rejected() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("firmware.pac");
    write_fixture(
        &source,
        &[
            FixtureEntry::file("image", "image.bin", b"payload"),
            FixtureEntry::operation("EraseMetadata"),
        ],
    );
    let mut pac = PacFile::new(&source).unwrap();
    for (offset, length) in [
        (8, 0),
        (7, 1),
        (u64::MAX, 1),
        (0, usize::MAX),
        (0, MAX_READ_BYTES + 1),
    ] {
        assert!(pac.read_range(&pac.entries[0], offset, length).is_err());
    }
    let mut forged = pac.entries[0].clone();
    forged.offset = 0;
    assert!(pac.read(&forged).is_err());
    pac.entries[0] = forged.clone();
    assert!(pac.read(&forged).is_err());
    assert!(
        pac.extract(&pac.entries[1], &dir.path().join("operation"))
            .is_err()
    );
}

#[test]
fn xml_limits_ambiguity_dtd_and_invalid_encoding_are_rejected() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("firmware.pac");
    for bytes in [
        b"<!DOCTYPE a [<!ENTITY x 'bad'>]><a>&x;</a>".as_slice(),
        b"\xff\xfe<",
        b"<x>",
    ] {
        write_fixture(&source, &[FixtureEntry::file("", "config.xml", bytes)]);
        assert!(PacFile::new(&source).unwrap().xml_text().is_err());
    }
    write_fixture(
        &source,
        &[
            FixtureEntry::file("", "a.xml", b"<a/>"),
            FixtureEntry::file("", "b.xml", b"<b/>"),
        ],
    );
    assert!(PacFile::new(&source).unwrap().xml_text().is_err());
    let mut large = FixtureEntry::file("", "large.xml", b"<a/>");
    large.size = MAX_READ_BYTES as u64 + 1;
    write_fixture(&source, &[large]);
    assert!(PacFile::new(&source).unwrap().xml_text().is_err());
}

#[test]
fn entry_sha256_matches_known_digest() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("firmware.pac");
    write_fixture(&source, &[FixtureEntry::file("image", "image.bin", b"abc")]);
    let pac = PacFile::new(source).unwrap();
    assert_eq!(
        pac.hash_entry(&pac.entries[0]).unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn real_pac_manifest_and_xml_match_when_inputs_are_supplied() {
    let (Ok(path), Ok(manifest)) = (
        std::env::var("RGROTATE_TEST_PAC"),
        std::env::var("RGROTATE_TEST_MANIFEST"),
    ) else {
        return;
    };
    let pac = PacFile::new(path).unwrap();
    let expected: serde_json::Value = serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
    assert_eq!(pac.size, expected["size"].as_u64().unwrap());
    assert_eq!(pac.version, expected["version"].as_str().unwrap());
    assert_eq!(pac.product, expected["product"].as_str().unwrap());
    assert_eq!(pac.firmware, expected["firmware"].as_str().unwrap());
    let entries = expected["entries"].as_array().unwrap();
    assert_eq!(pac.entries.len(), entries.len());
    for (actual, expected) in pac.entries.iter().zip(entries) {
        assert_eq!(actual.id, expected["id"].as_str().unwrap());
        assert_eq!(actual.name, expected["file"].as_str().unwrap());
        assert_eq!(actual.size, expected["size"].as_u64().unwrap());
        assert_eq!(actual.offset, expected["offset"].as_u64().unwrap());
        assert_eq!(actual.flag as u64, expected["data"].as_u64().unwrap());
        assert_eq!(
            actual.check_flag as u64,
            expected["required"].as_u64().unwrap()
        );
    }
    let xml = pac
        .entries
        .iter()
        .find(|e| e.name.ends_with(".xml"))
        .unwrap();
    let mut source = File::open(&pac.path).unwrap();
    source.seek(SeekFrom::Start(xml.offset)).unwrap();
    let mut raw = vec![0u8; xml.size as usize];
    source.read_exact(&mut raw).unwrap();
    let dir = tempdir().unwrap();
    let output = dir.path().join("config.xml");
    pac.extract(xml, &output).unwrap();
    assert_eq!(fs::read(output).unwrap(), raw);
    assert!(pac.xml_text().unwrap().contains("BMAConfig"));
}
