#![allow(dead_code)]
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

pub const HEADER: usize = 2124;
pub const ENTRY: usize = 2580;

#[derive(Clone)]
pub struct FixtureEntry {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub offset: Option<u64>,
    pub flag: u32,
    pub check_flag: u32,
    pub fragments: Vec<(u64, Vec<u8>)>,
}

impl FixtureEntry {
    pub fn file(id: &str, name: &str, data: &[u8]) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            size: data.len() as u64,
            offset: None,
            flag: 1,
            check_flag: 1,
            fragments: vec![(0, data.to_vec())],
        }
    }
    pub fn operation(id: &str) -> Self {
        Self {
            id: id.into(),
            name: String::new(),
            size: 0,
            offset: Some(0),
            flag: 0,
            check_flag: 1,
            fragments: Vec::new(),
        }
    }
}

pub fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub fn put_wide(bytes: &mut [u8], offset: usize, capacity: usize, text: &str) {
    let encoded: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(encoded.len() + 2 <= capacity);
    bytes[offset..offset + capacity].fill(0);
    bytes[offset..offset + encoded.len()].copy_from_slice(&encoded);
}

/// Write by independently specified binary offsets; seek/set_len leave holes.
pub fn write_fixture(path: &Path, entries: &[FixtureEntry]) {
    let mut end = (HEADER + ENTRY * entries.len()) as u64;
    let positions: Vec<_> = entries
        .iter()
        .map(|entry| {
            let offset = entry.offset.unwrap_or(end);
            end = end.max(offset.checked_add(entry.size).unwrap());
            offset
        })
        .collect();
    let mut header = [0u8; HEADER];
    put_wide(&mut header, 0, 44, "BP_R2.0.1");
    put_u32(&mut header, 44, (end >> 32) as u32);
    put_u32(&mut header, 48, end as u32);
    put_wide(&mut header, 52, 512, "ums512_1h10");
    put_wide(&mut header, 564, 512, "1.4.1");
    put_u32(&mut header, 1076, entries.len() as u32);
    put_u32(&mut header, 1080, HEADER as u32);
    put_u32(&mut header, 2116, 0xfffa_fffa);
    let mut file = File::create(path).unwrap();
    file.write_all(&header).unwrap();
    for (entry, &offset) in entries.iter().zip(&positions) {
        let mut raw = [0u8; ENTRY];
        put_u32(&mut raw, 0, ENTRY as u32);
        put_wide(&mut raw, 4, 512, &entry.id);
        put_wide(&mut raw, 516, 512, &entry.name);
        put_u32(&mut raw, 1532, (entry.size >> 32) as u32);
        put_u32(&mut raw, 1536, (offset >> 32) as u32);
        put_u32(&mut raw, 1540, entry.size as u32);
        put_u32(&mut raw, 1544, entry.flag);
        put_u32(&mut raw, 1548, entry.check_flag);
        put_u32(&mut raw, 1552, offset as u32);
        put_u32(&mut raw, 1560, 1);
        put_u32(&mut raw, 1564, 0x5500);
        file.write_all(&raw).unwrap();
    }
    file.set_len(end).unwrap();
    for (entry, &offset) in entries.iter().zip(&positions) {
        for (relative, bytes) in &entry.fragments {
            file.seek(SeekFrom::Start(offset + relative)).unwrap();
            file.write_all(bytes).unwrap();
        }
    }
}

pub fn patch(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(bytes).unwrap();
}
