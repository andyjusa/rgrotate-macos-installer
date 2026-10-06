"""Read BP_R2.0.1 Unisoc PAC archives without truncating 64-bit fields.

The binary field layout was checked against bismoy-bot/PAC-Extractor,
commit 7d4e59b6a5ba86a7ea4e8c42d9c5f229037a6893 (MIT; see third_party).
This implementation uses only the Python standard library. Parsing validates
structure and ranges, not firmware authenticity or the payload CRC.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import struct
import tempfile
from typing import BinaryIO, Iterator
import xml.etree.ElementTree as ET


HEADER_SIZE = 2124
ENTRY_SIZE = 2580
PAC_MAGIC = 0xFFFAFFFA
SUPPORTED_VERSIONS = frozenset({"BP_R2.0.1"})
MAX_ENTRIES = 4096
MAX_READ_BYTES = 16 * 1024 * 1024
DEFAULT_CHUNK_BYTES = 1024 * 1024


class PacError(ValueError):
    """Malformed, unsupported, changed, or incompletely read PAC archive."""


@dataclass(frozen=True)
class PacEntry:
    """One archive entry; index, rather than ID or filename, is its identity."""

    index: int
    id: str
    name: str
    size: int
    offset: int
    flag: int
    check_flag: int
    omit_flag: int
    addresses: tuple[int, ...]

    @property
    def file_flag(self) -> int:
        return self.flag

    @property
    def data_offset(self) -> int:
        return self.offset


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _wide(data: bytes, label: str) -> str:
    # Stop on a UTF-16 code-unit boundary, never on an arbitrary zero byte.
    end = len(data)
    for position in range(0, end, 2):
        if data[position : position + 2] == b"\x00\x00":
            end = position
            break
    try:
        return data[:end].decode("utf-16le", errors="strict")
    except UnicodeDecodeError as exc:
        raise PacError(f"Invalid UTF-16 in {label}") from exc


def _filename(name: str, label: str) -> None:
    # PAC filenames are basenames. Reject Windows paths as well on macOS/Linux.
    if (
        name in {".", ".."}
        or any(character in name for character in "/\\:")
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise PacError(f"Unsafe filename in {label}: {name!r}")


def _read_exact(stream: BinaryIO, length: int, label: str) -> bytes:
    data = stream.read(length)
    if len(data) != length:
        raise PacError(f"Unexpected EOF reading {label}: wanted {length}, got {len(data)}")
    return data


def _signature(status: os.stat_result) -> tuple[int, int, int, int, int]:
    return (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns, status.st_ctime_ns)


@contextmanager
def _open_regular(path: Path) -> Iterator[BinaryIO]:
    # A replaced archive path must not hang on a FIFO or read from a device.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise PacError("PAC source must be a regular file")
        stream = os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise
    with stream:
        yield stream


class PacFile:
    """Immutable metadata and bounded, read-only access to an on-disk PAC.

    ``version`` is the PAC format version; ``firmware`` is the product firmware
    version. Duplicate IDs and filenames are deliberately retained in entries.
    Only BP_R2.0.1 is supported; other layouts need independent validation first.
    Each subsequent read checks that the source still matches the parsed file.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path).expanduser().resolve(strict=True)
        self._xml_text: str | None = None
        self._xml_root: ET.Element | None = None
        with _open_regular(self.path) as source:
            status = os.fstat(source.fileno())
            self._signature = _signature(status)
            self.size = status.st_size
            if self.size < HEADER_SIZE:
                raise PacError("File is too small for a PAC header")
            header = _read_exact(source, HEADER_SIZE, "PAC header")
            self.version = _wide(header[:44], "PAC version")
            if self.version not in SUPPORTED_VERSIONS:
                raise PacError(f"Unsupported PAC version: {self.version!r}")
            if _u32(header, 2116) != PAC_MAGIC:
                raise PacError("Invalid PAC magic")
            declared_size = (_u32(header, 44) << 32) | _u32(header, 48)
            if declared_size != self.size:
                raise PacError(f"PAC size mismatch: header {declared_size}, file {self.size}")
            self.product = _wide(header[52:564], "product")
            self.firmware = _wide(header[564:1076], "firmware version")
            self.alias = _wide(header[1104:1304], "product alias")
            self.mode = _u32(header, 1084)
            self.flash_type = _u32(header, 1088)
            self.crc1, self.crc2 = struct.unpack_from("<HH", header, 2120)
            count = _u32(header, 1076)
            table_offset = _u32(header, 1080)
            if not 0 < count <= MAX_ENTRIES:
                raise PacError(f"Invalid PAC entry count: {count}")
            if table_offset < HEADER_SIZE or table_offset > self.size:
                raise PacError("PAC entry table lies outside the archive")
            table_length = count * ENTRY_SIZE
            if table_length > self.size - table_offset:
                raise PacError("PAC entry table extends beyond EOF")
            table_end = table_offset + table_length
            source.seek(table_offset)
            entries = []
            for index in range(count):
                raw = _read_exact(source, ENTRY_SIZE, f"entry {index}")
                if _u32(raw, 0) != ENTRY_SIZE:
                    raise PacError(f"Unsupported entry size at index {index}")
                size = (_u32(raw, 1532) << 32) | _u32(raw, 1540)
                offset = (_u32(raw, 1536) << 32) | _u32(raw, 1552)
                flag = _u32(raw, 1544)
                if flag not in {0, 1, 2}:
                    raise PacError(f"Unsupported file flag {flag} at index {index}")
                if offset > self.size or size > self.size - offset:
                    raise PacError(f"Entry {index} data range extends beyond EOF")
                if size and offset < table_end:
                    raise PacError(f"Entry {index} data overlaps the PAC metadata")
                if flag == 0 and size:
                    raise PacError(f"Operation-only entry {index} unexpectedly contains data")
                address_count = _u32(raw, 1560)
                if address_count > 5:
                    raise PacError(f"Too many addresses at entry {index}")
                name = _wide(raw[516:1028], f"entry {index} filename")
                _filename(name, f"entry {index}")
                if size and not name:
                    raise PacError(f"Data entry {index} has no filename")
                entries.append(
                    PacEntry(
                        index=index,
                        id=_wide(raw[4:516], f"entry {index} ID"),
                        name=name,
                        size=size,
                        offset=offset,
                        flag=flag,
                        check_flag=_u32(raw, 1548),
                        omit_flag=_u32(raw, 1556),
                        addresses=struct.unpack_from(f"<{address_count}I", raw, 1564),
                    )
                )
            # Distinct payloads cannot share bytes. Duplicate IDs or basenames
            # are valid and remain distinct as long as their ranges differ.
            end = table_end
            for entry in sorted((item for item in entries if item.size), key=lambda item: item.offset):
                if entry.offset < end:
                    raise PacError(f"Overlapping payload range at entry {entry.index}")
                end = entry.offset + entry.size
            self.entries = tuple(entries)
            self._assert_unchanged(source)

    @property
    def product_name(self) -> str:
        return self.product

    @property
    def pac_size(self) -> int:
        return self.size

    def entries_for_id(self, identifier: str) -> tuple[PacEntry, ...]:
        """Return every matching entry, including repeated UBOOTLoader IDs."""
        return tuple(entry for entry in self.entries if entry.id == identifier)

    def _assert_unchanged(self, source: BinaryIO) -> None:
        if _signature(os.fstat(source.fileno())) != self._signature:
            raise PacError("PAC source changed after it was parsed")

    def _check_entry(self, entry: PacEntry) -> None:
        if (
            not isinstance(entry, PacEntry)
            or not 0 <= entry.index < len(self.entries)
            or self.entries[entry.index] is not entry
        ):
            raise PacError("Entry does not belong to this PAC instance")

    def iter_chunks(self, entry: PacEntry, chunk_size: int = DEFAULT_CHUNK_BYTES) -> Iterator[bytes]:
        """Yield all payload bytes with a bounded allocation and exact EOF checks."""
        self._check_entry(entry)
        if not isinstance(chunk_size, int) or not 0 < chunk_size <= MAX_READ_BYTES:
            raise PacError(f"Chunk size must be between 1 and {MAX_READ_BYTES}")
        with _open_regular(self.path) as source:
            self._assert_unchanged(source)
            source.seek(entry.offset)
            remaining = entry.size
            while remaining:
                chunk = _read_exact(source, min(remaining, chunk_size), f"entry {entry.index}")
                remaining -= len(chunk)
                yield chunk
            self._assert_unchanged(source)

    def read_range(self, entry: PacEntry, offset: int, length: int) -> bytes:
        """Read a bounded range relative to an entry, including offsets >4 GiB."""
        self._check_entry(entry)
        if not isinstance(offset, int) or not isinstance(length, int):
            raise PacError("Read range must use integer offsets and lengths")
        if offset < 0 or length < 0 or offset > entry.size or length > entry.size - offset:
            raise PacError("Read range lies outside the PAC entry")
        if length > MAX_READ_BYTES:
            raise PacError(f"Read range exceeds {MAX_READ_BYTES} bytes; use iter_chunks")
        with _open_regular(self.path) as source:
            self._assert_unchanged(source)
            source.seek(entry.offset + offset)
            data = _read_exact(source, length, f"entry {entry.index}")
            self._assert_unchanged(source)
            return data

    def read(self, entry: PacEntry, max_bytes: int = MAX_READ_BYTES) -> bytes:
        """Read a small entry; large images must be streamed or extracted."""
        self._check_entry(entry)
        if not isinstance(max_bytes, int) or not 0 <= max_bytes <= MAX_READ_BYTES:
            raise PacError(f"max_bytes must be between 0 and {MAX_READ_BYTES}")
        if entry.size > max_bytes:
            raise PacError(f"Entry {entry.index} exceeds the in-memory read limit")
        return self.read_range(entry, 0, entry.size)

    def extract(self, entry: PacEntry, outpath: str | os.PathLike[str]) -> Path:
        """Extract to an exact caller-chosen filename, refusing existing targets.

        Temporary output is placed in the target directory and linked into place
        only after every byte is written. Failure leaves no partial target; an
        existing file or symlink is never followed or overwritten. The archived
        filename is not joined to the caller's output path.
        """
        self._check_entry(entry)
        if entry.flag == 0:
            raise PacError(f"Entry {entry.index} is an operation, not a file")
        target = Path(outpath).expanduser()
        if target.name in {"", ".", ".."}:
            raise PacError("Extraction target must be a filename")
        if target.is_symlink() or target.exists():
            raise FileExistsError(f"Extraction target already exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        # Resolve the caller-chosen directory once; never resolve the filename.
        target = target.parent.resolve(strict=True) / target.name
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(prefix=".rgrotate-", dir=target.parent, delete=False) as output:
                temporary = output.name
                for chunk in self.iter_chunks(entry):
                    written = output.write(chunk)
                    if written != len(chunk):
                        raise OSError("Short write while extracting PAC entry")
                output.flush()
                os.fsync(output.fileno())
            # link() creates the destination atomically and fails if it exists,
            # including a symlink created since the earlier path check.
            os.link(temporary, target)
            return target
        finally:
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)

    extract_entry = extract

    def _load_xml(self) -> None:
        candidates = [entry for entry in self.entries if entry.flag and entry.name.lower().endswith(".xml")]
        if len(candidates) != 1:
            raise PacError(f"Expected one embedded XML entry, found {len(candidates)}")
        raw = self.read(candidates[0])
        try:
            if raw.startswith(b"\xff\xfe"):
                text = raw[2:].decode("utf-16le")
            elif raw.startswith(b"\xfe\xff"):
                text = raw[2:].decode("utf-16be")
            elif raw.startswith(b"<\x00"):
                text = raw.decode("utf-16le")
            elif raw.startswith(b"\x00<"):
                text = raw.decode("utf-16be")
            else:
                text = raw.decode("utf-8-sig")
            text = text.rstrip("\x00")
            if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
                raise PacError("Embedded XML declarations for DTDs/entities are unsupported")
            root = ET.fromstring(text)
        except (UnicodeDecodeError, ET.ParseError) as exc:
            raise PacError(f"Invalid embedded XML: {exc}") from exc
        self._xml_text = text
        self._xml_root = root

    @property
    def xml_text(self) -> str:
        if self._xml_text is None:
            self._load_xml()
        return self._xml_text

    @property
    def xml_root(self) -> ET.Element:
        if self._xml_root is None:
            self._load_xml()
        return self._xml_root
