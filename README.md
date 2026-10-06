# RG Rotate macOS Installer

Community tooling for using an Anbernic RG Rotate PAC firmware package on macOS.
This project follows the Unisoc BootROM/FDL transport used by PAC installers.
It is independent of Anbernic and GammaOS and is not an official macOS release.

**Development preview: inspection and read-only probing are being validated.
Full firmware installation is blocked until the complete write and recovery
workflow has been verified. Do not treat a successful build or PAC inspection
as proof that a device can be safely flashed.**

## Current capabilities

- Read BP_R2.0.1 PAC files with 64-bit image sizes and offsets, including files
  larger than 4 GiB.
- Inspect the firmware product, partition layout, ordered operations, and
  preservation requirements without opening USB.
- Preserve duplicate PAC IDs and XML operation ordering.
- Build a native libusb backend on macOS.
- Run an explicit read-only probe: execute the package's FDL loaders in RAM,
  read the partition table and the first 1 MiB of `boot_a`, then power off.
- Refuse unsupported or ambiguous destructive operations before device writes.

The probe does not erase, repartition, or write device storage. Executing an
FDL still requires the correct device model and the matching firmware loaders.
Its sample hash must be compared with a trusted baseline; a completed USB read
alone does not establish device identity or flashing compatibility.

## Build and inspect

Requirements: macOS, Xcode Command Line Tools, Python 3.10+, `pkg-config`, and
`libusb`.

```sh
brew install pkg-config libusb
sh scripts/build-macos.sh
python3 -m unittest discover -s tests -v
python3 -m rgrotate plan /path/to/official-firmware.pac
```

The Python inspection commands use only the standard library. Firmware,
passwords, downloaded archives, and device backups are not distributed.
Obtain your own firmware from the
[official RG Rotate release](https://github.com/TheGammaSqueeze/GammaOSNext/releases/tag/v1.4.1-ANBERNICRGROTATE).

## Validation status

Validated on Apple Silicon macOS during development:

- 43 Python tests, including comparison of all 71 entries in the 6.67 GB
  GammaOS Full v1.4.1 PAC with an independent manifest.
- Native backend build with warnings treated as errors.
- Mock USB/protocol tests under AddressSanitizer and UndefinedBehaviorSanitizer:
  64-bit transfer lengths, short reads, invalid acknowledgements, deadlines,
  multiple-device rejection, and streaming failures.
- Offline command classification accepts the probe sequence and rejects a
  destructive command under `--read-only` before USB initialization.

Actual BootROM/FDL communication and a full installation on RG Rotate remain
unverified. Firmware integration tests require local `RGROTATE_TEST_PAC` and
`RGROTATE_TEST_MANIFEST` paths; those inputs are not distributed.

## Read-only USB probe

Prepare a fresh output directory. The command refuses an existing directory.

```sh
python3 -m rgrotate probe /path/to/official-firmware.pac \
  --backend ./build/spd_dump --out ./runs/probe-001 --wait 30
```

For the RG Rotate, remove the microSD, power the device off, open the sliding
screen, hold the center Back button, and connect USB while the tool is waiting.
See the model-specific
[official instructions](https://github.com/TheGammaSqueeze/GammaOSNext/wiki/GammaOS-Next-Installation#anbernic-rg-rotate).

The output directory contains loader copies, probe logs, the partition table,
and the boot sample. Keep it private. A failure stops the operation; the program
does not automatically reconnect or retry a write.

## Why a separate implementation?

The available PAC tools differ in supported archive versions, USB behavior,
and handling of vendor-specific operations. This project makes those
differences explicit and refuses operations it cannot verify. Its firmware
inspection and native transport are separate so that malformed PAC files and
unsupported flash plans can be rejected before USB is opened.

## Licensing

Original project code is MIT licensed. The vendored `spreadtrum_flash` backend
is covered by the Unlicense; its pinned upstream revision and license are in
`vendor/spreadtrum_flash`. Format references and any additional notices are
listed in `THIRD_PARTY_NOTICES.md`. Firmware and vendor loaders are not covered
by this project's license and are not included.
