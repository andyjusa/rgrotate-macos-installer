# RG Rotate macOS Installer

Native Rust tooling for using an Anbernic RG Rotate PAC firmware package on macOS.
The CLI, PAC parser, validation, and installation runner require no Python runtime.
USB packets are handled by the existing audited C/libusb backend.
This project follows the Unisoc BootROM/FDL transport used by PAC installers.
It is independent of Anbernic and GammaOS and is not an official macOS release.

**Development preview: the native C backend has communicated with an RG Rotate
using BootROM/FDL. The Rust orchestration is tested offline; its complete physical
installation and recovery-reset workflow remains experimental.**

## Current capabilities

- Read BP_R2.0.1 PAC files with 64-bit image sizes and offsets, including files
  larger than 4 GiB.
- Inspect the firmware product, partition layout, ordered operations, and
  preservation requirements without opening USB.
- Preserve duplicate PAC IDs and XML operation ordering.
- Build a native libusb backend on macOS.
- Run an explicit read-only probe: execute the package's FDL loaders in RAM,
  read the partition table and the first 1 MiB of `boot_a`, then power off.
- Install the pinned Full image on a compatible existing layout with complete
  readback checks, then request a Recovery factory reset.
- Refuse unsupported or ambiguous destructive operations before device writes.

The probe does not erase, repartition, or write device storage. Executing an
FDL still requires the correct device model and the matching firmware loaders.
Its sample hash must be compared with a trusted baseline; a completed USB read
alone does not establish device identity or flashing compatibility.

## Build and inspect

Requirements: macOS, Xcode Command Line Tools, Rust/Cargo 1.85 or newer,
`pkg-config`, and `libusb`. Install Rust from [rustup](https://rustup.rs).

```sh
brew install pkg-config libusb
sh scripts/build-macos.sh
cargo test --locked
make -C vendor/spreadtrum_flash test
./build/rgrotate plan /path/to/official-firmware.pac
```

The build produces `build/rgrotate` and `build/spd_dump`. Offline plan inspection
uses only the Rust binary; device commands explicitly select the backend. Firmware,
passwords, downloaded archives, and device backups are not distributed.
Obtain your own firmware from the
[official RG Rotate release](https://github.com/TheGammaSqueeze/GammaOSNext/releases/tag/v1.4.1-ANBERNICRGROTATE).

## Validation status

Validated on Apple Silicon macOS during development:

- Rust parser, planner, validation, CLI, and subprocess-runner regressions.
- Optional real-firmware integration compares all 71 entries in the 6.67 GB
  GammaOS Full v1.4.1 PAC with an independent manifest.
- Native backend build with warnings treated as errors.
- Mock USB/protocol tests under AddressSanitizer and UndefinedBehaviorSanitizer:
  64-bit transfer lengths, short reads, invalid acknowledgements, deadlines,
  multiple-device rejection, and streaming failures.
- Offline command classification accepts the probe sequence and rejects a
  destructive command under `--read-only` before USB initialization.
- Actual BootROM/FDL loader execution, preflight reads, Full `super`, four
  A-side vbmeta images, and patched `misc` writes through the native macOS
  backend with the prior Python orchestrator. All six complete readbacks
  matched their expected SHA-256 hashes and power-off succeeded. This does
  not establish Rust orchestration or Recovery/Android boot validation.

The Rust clean Full conversion and recovery factory reset remain unverified on
hardware. Native-backend results and offline Rust tests are recorded separately;
a successful probe does not establish the complete install outcome.
Firmware integration tests require local
`RGROTATE_TEST_PAC` and `RGROTATE_TEST_MANIFEST` paths; those inputs are not
distributed. `RGROTATE_TEST_PLAN` optionally supplies an independent reference
plan JSON. `RGROTATE_TEST_PREFLIGHT` optionally points to complete saved preflight
reads, including `before/` and `images/misc.bin`, for validation and BCB parity
checks. All these integration tests read local files and never open USB.

## Read-only USB probe

Prepare a fresh output directory. The command refuses an existing directory.

```sh
./build/rgrotate probe /path/to/official-firmware.pac \
  --backend ./build/spd_dump --out ./runs/probe-001 --wait 120
```

For the RG Rotate, remove the microSD, power the device off, open the sliding
screen, hold the center Back button, and connect USB while the tool is waiting.
See the model-specific
[official instructions](https://github.com/TheGammaSqueeze/GammaOSNext/wiki/GammaOS-Next-Installation#anbernic-rg-rotate).

The output directory contains loader copies, probe logs, the partition table,
and the boot sample. Keep it private. A failure stops the operation; the program
does not automatically reconnect or retry a write.

## Clean Full conversion (experimental)

The experimental installation path targets the official **GammaOS Next
v1.4.1 Full PAC** and an RG Rotate with a compatible existing boot chain and
partition layout. It keeps the existing GPT, NV/calibration data, and compatible
boot-chain images, then performs this bounded sequence through the PAC's FDLs:

1. Write the PAC's raw `full_super.img` to `super` and read the complete written
   image back for a SHA-256 comparison.
2. Write the four A-side vbmeta images and verify each complete readback.
3. Read the current `misc` image and change only its recovery command fields to
   request `recovery --wipe_data`, preserving the remaining bytes. Write and
   verify the complete patched image.
4. Power off. The next boot is requested to enter recovery and perform the
   factory reset; that boot outcome still needs hardware verification.

Use a new output directory. An existing directory is refused, so an interrupted
run cannot silently overwrite its pre-write backups or verification evidence.

```sh
./build/rgrotate flash /path/to/official-v1.4.1-full.pac \
  --flash --preserve-layout --wipe-data \
  --backend ./build/spd_dump --out ./runs/install-001 --wait 120
```

Keep the device disconnected while the tool checks the pinned Full images,
extracts them locally, and checks space for complete readback files. Connect in
the model-specific BootROM mode above when the tool reports that it is waiting.
All three options `--flash --preserve-layout --wipe-data` are required for this
installation path.

Before the first write, the runner reads the device partition table, compatible
boot-chain images, current `misc`, and device-specific NV/calibration regions.
It also reads a 1 MiB range of `super` at an offset above 4 GiB to exercise the
device's 64-bit read path. The preflight validator must accept these results
before any write confirmation is sent.

Every write is followed by a complete size and SHA-256 check of its readback.
Only then is the next write allowed. The output directory contains private
pre-write backups, extracted images, full readbacks, `install.log`,
`progress.json`, and an atomically updated `install-result.json`. A failure
stops the connection; there is no automatic retry, reconnect, or reset.

`storage_verified_awaiting_recovery_boot` means the written images were read
back successfully and power-off was acknowledged. It does not mean Android
booted or the factory reset finished. The result keeps `boot_verified` false
until that separate outcome has been checked.

This is a targeted Full conversion over native macOS FDL. It does not replay
the Windows installer's complete PAC operation sequence or repartition the
device. Generic `--full-flash` execution is unsupported.

The explicit wipe request removes user data, games stored in userdata, saves,
and settings. The installer does not restore them. The hardware write and
first-boot reset workflow must still be validated before this path can be
described as a verified installer.

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
