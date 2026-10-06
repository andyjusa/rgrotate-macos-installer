"""Offline checks for one pinned RG Rotate GammaOS Next 1.4.1 Full PAC.

This module performs no USB operations or writes. Partition-list checks cover
reported names and MiB sizes, not raw GPT LBAs or CRCs. Boot-control layouts:
https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/android14-release/boot/1.1/default/boot_control/include/private/boot_control_definition.h
https://android.googlesource.com/platform/bootable/recovery/+/refs/heads/android14-release/bootloader_message/include/bootloader_message/bootloader_message.h
MergeStatus.NONE is 0; UNKNOWN, SNAPSHOTTED, MERGING, and CANCELLED are rejected:
https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/android14-release/boot/1.1/types.hal
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import struct
import weakref
import xml.etree.ElementTree as ET
import zlib

from .pac import PacError


MIB = 1024 * 1024
PAC_SIZE = 6674491170
PAC_SHA256 = '92b924a8baf2d83ec2f19d734daf5588a0a825596ee2ced285c98244b9d01208'
EXPECTED_PARTITIONS = {
    'prodnv': 10, 'miscdata': 1, 'misc': 1,
    'trustos_a': 6, 'trustos_b': 6, 'sml_a': 1, 'sml_b': 1,
    'uboot_a': 3, 'uboot_b': 3, 'uboot_log': 4, 'logo': 8, 'fbootlogo': 8,
    'l_fixnv1_a': 2, 'l_fixnv2_a': 2, 'l_fixnv1_b': 2, 'l_fixnv2_b': 2,
    'l_runtimenv1': 2, 'l_runtimenv2': 2,
    'gnssmodem_a': 1, 'gnssmodem_b': 1, 'wcnmodem_a': 10, 'wcnmodem_b': 10,
    'persist': 2, 'l_modem_a': 25, 'l_modem_b': 25,
    'l_deltanv_a': 1, 'l_deltanv_b': 1, 'l_gdsp_a': 10, 'l_gdsp_b': 10,
    'l_ldsp_a': 20, 'l_ldsp_b': 20, 'l_agdsp_a': 6, 'l_agdsp_b': 6,
    'l_cdsp_a': 1, 'l_cdsp_b': 1, 'pm_sys_a': 1, 'pm_sys_b': 1,
    'teecfg_a': 1, 'teecfg_b': 1, 'hypervsior_a': 10, 'hypervsior_b': 10,
    'boot_a': 64, 'boot_b': 64, 'vendor_boot_a': 100, 'vendor_boot_b': 100,
    'init_boot_a': 8, 'init_boot_b': 8, 'dtb_a': 8, 'dtb_b': 8,
    'dtbo_a': 8, 'dtbo_b': 8, 'super': 5600, 'cache': 100,
    'vbmeta_a': 1, 'vbmeta_b': 1, 'metadata': 16, 'sysdumpdb': 10,
    'vbmeta_system_a': 1, 'vbmeta_system_b': 1,
    'vbmeta_vendor_a': 1, 'vbmeta_vendor_b': 1,
    'vbmeta_system_ext_a': 1, 'vbmeta_system_ext_b': 1,
    'vbmeta_product_a': 1, 'vbmeta_product_b': 1,
    'vbmeta_odm_a': 1, 'vbmeta_odm_b': 1, 'avbmeta_rs_a': 1, 'avbmeta_rs_b': 1,
    'common_rs1_a': 8, 'common_rs1_b': 8, 'common_rs2_a': 16, 'common_rs2_b': 16,
    # The backend reports a remainder sentinel, not the physical userdata size.
    'userdata': 0xffffffff,
}


@dataclass(frozen=True)
class ImageSpec:
    identifier: str
    filename: str
    size: int
    sha256: str


INSTALL_IMAGES = {
    'super': ImageSpec('Super', 'full_super.img', 5872025600,
        'ddd80890ce8cf3700ac3b989a9f441e5dbc98ff80d94757b34f9675169b777e8'),
    'vbmeta_system_a': ImageSpec('VBMETA_SYSTEM', 'vbmeta_system_a.img', MIB,
        '6083f4319806f24c81c65294d596bfb742f06fa2892b1b38e25feba1ce07d328'),
    'vbmeta_system_ext_a': ImageSpec('VBMETA_SYSTEM_EXT', 'vbmeta_system_ext_a.img', MIB,
        'cda0144a8a5c36495fcfabfecce7644973a8df66992a1cef1b85eba8fa5d7231'),
    'vbmeta_vendor_a': ImageSpec('VBMETA_VENDOR', 'vbmeta_vendor_a.img', MIB,
        '2c111f485e74e44675b2a0295262963f37910622d3ed39c76198a74dd907db3a'),
    'vbmeta_product_a': ImageSpec('VBMETA_PRODUCT', 'vbmeta_product_a.img', MIB,
        '9a45bd0a61a62cb6790da3a3941d36fac2cafe3c5c1365671c9dc0f6e7c953a9'),
}
BASELINE_IMAGES = {
    'boot_a': ImageSpec('BOOT', 'boot_a.img', 64 * MIB,
        'e3a43c0cd0b0a3b7ee3508d60b2cdca56121148f45f7ad3e6880781ad1a8621b'),
    'vendor_boot_a': ImageSpec('VENDORBOOT', 'vendor_boot_a.img', 100 * MIB,
        'f76bcb7bf070177865554aaf5491279827eecd912891ffb9315733573365a2dd'),
    'init_boot_a': ImageSpec('INITBOOT', 'init_boot_a.img', 8 * MIB,
        '2daeb1f36095b44b318410b3f4e8b5d989dcc7bb023d1426c492dab0a3053e74'),
    'dtbo_a': ImageSpec('DTBO', 'dtbo_a.img', 8 * MIB,
        'a0c2cc17861b31fbc51fb7cd655404449689d54eb3ea2c01cc2a246fbda16f46'),
    'vbmeta_a': ImageSpec('VBMETA', 'vbmeta_a.img', MIB,
        '4ed57d1968c1ab06cfa3cca750a310be3a04fe1b646701a75da9af4374f5b84e'),
}
NV_PARTITIONS = (
    'prodnv', 'miscdata', 'persist', 'l_fixnv1_a', 'l_fixnv2_a',
    'l_fixnv1_b', 'l_fixnv2_b', 'l_runtimenv1', 'l_runtimenv2',
    'l_deltanv_a', 'l_deltanv_b',
)
REQUIRED_BEFORE_READS = {
    name: EXPECTED_PARTITIONS[name] * MIB
    for name in (*BASELINE_IMAGES, 'misc',
                 *(name for name in INSTALL_IMAGES if name != 'super'), *NV_PARTITIONS)
}
_VALIDATED_PACS = weakref.WeakKeyDictionary()


class InstallError(RuntimeError):
    """An input or saved device state is incompatible with this install route."""


def _signature(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


@contextmanager
def _regular_file(path):
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
        try:
            original = os.fstat(fd)
            if not stat.S_ISREG(original.st_mode):
                raise InstallError(f'{path.name}: expected a regular file')
            stream = os.fdopen(fd, 'rb')
        except BaseException:
            os.close(fd)
            raise
        with stream:
            yield stream, original.st_size
            if (_signature(original) != _signature(os.fstat(stream.fileno())) or
                    _signature(original) != _signature(path.stat())):
                raise InstallError(f'{path.name}: file changed during validation')
    except OSError as exc:
        raise InstallError(f'{path.name}: cannot read validation input: {exc.strerror}') from exc


def _hash_file(path, expected_size=None):
    digest = hashlib.sha256()
    with _regular_file(path) as (source, size):
        if expected_size is not None and size != expected_size:
            raise InstallError(f'{Path(path).name}: length {size}, expected {expected_size}')
        count = 0
        while chunk := source.read(MIB):
            digest.update(chunk)
            count += len(chunk)
        if count != size:
            raise InstallError(f'{Path(path).name}: incomplete read')
    return digest.hexdigest()


def sha256_file(path):
    """Hash every byte of a stable regular file with bounded memory."""
    return _hash_file(path)


def _read_file(path, *, exact=None, maximum=MIB):
    with _regular_file(path) as (source, size):
        if size > maximum or (exact is not None and size != exact):
            raise InstallError(f'{Path(path).name}: invalid length {size}')
        data = source.read(size + 1)
        if len(data) != size:
            raise InstallError(f'{Path(path).name}: incomplete read')
    return data


def _entry(pac, partition, spec):
    entries = pac.entries_for_id(spec.identifier)
    if len(entries) != 1:
        raise InstallError(f'{partition}: exactly one PAC image is required')
    entry = entries[0]
    if entry.name != spec.filename or entry.size != spec.size or entry.flag != 1:
        raise InstallError(f'{partition}: unexpected PAC image metadata')
    nodes = [n for n in pac.xml_root.iter('File') if n.findtext('ID') == spec.identifier]
    if len(nodes) != 1 or nodes[0].find('Block') is None:
        raise InstallError(f'{partition}: missing or ambiguous XML mapping')
    if nodes[0].find('Block').get('id') != partition:
        raise InstallError(f'{partition}: incorrect XML partition mapping')
    return entry


def validate_pac(pac):
    """Authenticate the pinned archive and return its five writable images.

    Complete this before opening USB. The successful check is tied to this
    PacFile object and source-file identity, allowing preflight to avoid a
    second multi-GiB read while the device is waiting in FDL.
    """
    _VALIDATED_PACS.pop(pac, None)
    try:
        if (pac.product != 'ums512_1h10' or pac.firmware != '1.4.1' or
                pac.version != 'BP_R2.0.1' or pac.size != PAC_SIZE):
            raise InstallError('Only the pinned RG Rotate GammaOS Next 1.4.1 Full PAC is supported')
        if _hash_file(pac.path, PAC_SIZE) != PAC_SHA256:
            raise InstallError('PAC SHA-256 does not match the pinned official Full release')
        images = {}
        for partition, spec in {**INSTALL_IMAGES, **BASELINE_IMAGES}.items():
            entry = _entry(pac, partition, spec)
            digest = hashlib.sha256()
            count = 0
            for chunk in pac.iter_chunks(entry):
                digest.update(chunk)
                count += len(chunk)
            if count != spec.size or digest.hexdigest() != spec.sha256:
                raise InstallError(f'{partition}: official image SHA-256/length mismatch')
            if partition == 'super' and pac.read_range(entry, 0, 4) == b'\x3a\xff\x26\xed':
                raise InstallError('Sparse super is unsupported; a verified RAW image is required')
            if partition in INSTALL_IMAGES:
                images[partition] = {'entry': entry, 'sha256': spec.sha256, 'size': spec.size}
        _VALIDATED_PACS[pac] = _signature(Path(pac.path).stat())
        return images
    except (PacError, OSError) as exc:
        raise InstallError(f'PAC validation failed: {exc}') from exc


def _validate_layout(data):
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise InstallError('Partition XML DTD/entity declarations are unsupported')
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise InstallError('Malformed partition-list XML') from exc
    if root.tag != 'Partitions' or root.attrib:
        raise InstallError('Unexpected partition-list XML root')
    actual = {}
    for node in root:
        if node.tag != 'Partition' or set(node.attrib) != {'id', 'size'} or len(node):
            raise InstallError('Unexpected partition-list XML element')
        name = node.get('id')
        if name in actual:
            raise InstallError(f'Duplicate partition in device layout: {name}')
        try:
            value = node.get('size')
            size = int(value, 16) if value.lower().startswith('0x') else int(value, 10)
        except (ValueError, AttributeError) as exc:
            raise InstallError(f'Invalid partition size for {name}') from exc
        actual[name] = size
    if actual != EXPECTED_PARTITIONS:
        missing = sorted(EXPECTED_PARTITIONS.keys() - actual.keys())
        extra = sorted(actual.keys() - EXPECTED_PARTITIONS.keys())
        changed = sorted(n for n in actual.keys() & EXPECTED_PARTITIONS.keys()
                         if actual[n] != EXPECTED_PARTITIONS[n])
        raise InstallError(f'Incompatible partition layout: missing={missing}, extra={extra}, size={changed}')
    return actual


def _validate_misc(data):
    if not isinstance(data, (bytes, bytearray)) or len(data) != MIB:
        raise InstallError('misc must contain the complete 1 MiB partition')
    if any(data[:32]):
        raise InstallError('BCB already contains a pending bootloader command')
    if any(data[832:864]):
        raise InstallError('BCB has a pending multistage recovery operation')
    control = data[2048:2080]
    if control[:4] != b'_a\0\0':
        raise InstallError('The active boot-control slot must be A')
    if struct.unpack_from('<I', control, 4)[0] != 0x42414342 or control[8] != 1:
        raise InstallError('Unrecognized boot-control magic or version')
    if control[9] & 7 != 2:
        raise InstallError('Exactly two boot-control slots are required')
    if struct.unpack_from('<I', control, 28)[0] != zlib.crc32(control[:28]):
        raise InstallError('Boot-control CRC32 is invalid')
    # Packed uint8_t bitfields cross a byte: slots=bits72..74,
    # recovery_tries=75..77, merge_status=78..80 (not byte 10 bits0..2).
    merge_status = (control[9] >> 6) | ((control[10] & 1) << 2)
    if merge_status:
        raise InstallError('Boot-control reports a pending snapshot merge')
    priority_a, priority_b = control[12] & 15, control[14] & 15
    if not priority_a or not control[12] & 0x80 or control[13] & 1:
        raise InstallError('Slot A must be successful, bootable, and free of verity corruption')
    if priority_a <= priority_b:
        raise InstallError('Slot A must have strictly greater boot priority than B')
    virtual_ab = data[32768:32832]
    if not any(virtual_ab):
        raise InstallError('Virtual A/B status is uninitialized; absence of snapshots is unverified')
    if virtual_ab[0] != 2 or struct.unpack_from('<I', virtual_ab, 1)[0] != 0x56740ab0:
        raise InstallError('Unrecognized Virtual A/B status version or magic')
    if virtual_ab[5] != 0:
        raise InstallError('Virtual A/B snapshot status must be NONE (0)')
    if virtual_ab[6] not in (0, 1):
        raise InstallError('Virtual A/B source slot is invalid')
    return {'active_slot': 'a', 'slot_a_successful': True, 'bootctrl_crc32_valid': True,
            'snapshot_status': 'none', 'snapshot_source_slot': virtual_ab[6]}


def validate_preflight(out_dir, pac):
    """Check saved reads only; return JSON-compatible validation evidence."""
    try:
        signature = _VALIDATED_PACS.get(pac)
        if signature is None:
            raise InstallError('validate_pac must succeed on this PacFile before preflight')
        if signature != _signature(Path(pac.path).stat()):
            raise InstallError('PAC source changed after validation')
        # This also checks the PacFile parser's original inode/time snapshot.
        spec = BASELINE_IMAGES['boot_a']
        pac.read_range(_entry(pac, 'boot_a', spec), 0, 0)
        out = Path(out_dir)
        layout = _validate_layout(_read_file(out / 'partitions.xml'))
        before = {}
        misc = None
        for name, size in REQUIRED_BEFORE_READS.items():
            path = out / 'before' / f'{name}.bin'
            if name == 'misc':
                data = _read_file(path, exact=MIB)
                misc = _validate_misc(data)
                digest = hashlib.sha256(data).hexdigest()
            else:
                digest = _hash_file(path, size)
            if name in BASELINE_IMAGES and digest != BASELINE_IMAGES[name].sha256:
                raise InstallError(f'{name}: existing boot image differs from the official PAC')
            before[name] = {'size': size, 'sha256': digest}
        # Evidence that the >4 GiB named-read path completed before any write.
        # This records the old Lite tail; it is not a Full-content comparison.
        before['super-tail'] = {'size': MIB,
                                'sha256': _hash_file(out / 'before' / 'super-tail.bin', MIB)}
        return {'partition_layout': layout, 'before': before, 'misc': misc,
                'pac_sha256': PAC_SHA256,
                'limitations': ['Partition list validates names and reported MiB sizes, not raw GPT LBAs/CRCs.',
                                'Snapshot check validates the boot-control and misc Virtual A/B records; metadata files are not inspected.']}
    except (PacError, OSError) as exc:
        raise InstallError(f'Preflight validation failed: {exc}') from exc


def patch_misc(data):
    """Return a BCB wipe request preserving every byte outside two fields.

    Mirrors AOSP update_bootloader_message_in_struct(): clear/update command
    and recovery only. Never copy the PAC's misc/boot-control metadata.
    """
    _validate_misc(data)
    result = bytearray(data)
    result[:32] = b'boot-recovery'.ljust(32, b'\0')
    result[64:832] = b'recovery\n--wipe_data\n'.ljust(768, b'\0')
    return bytes(result)
