# Third-party notices

Original project code is covered by the repository's [MIT license](LICENSE).
The components and reference material below retain their respective licenses.

## spreadtrum_flash

- Upstream: [ilyakurdyukov/spreadtrum_flash](https://github.com/ilyakurdyukov/spreadtrum_flash)
- Pinned revision: `40c4ab9b89e6835b9145aaada37ee389eaca74ea`
- Upstream license: [Unlicense](vendor/spreadtrum_flash/LICENSE)
- Local directory: `vendor/spreadtrum_flash`

The native backend is derived from this upstream project. Its source and build
files include local changes for macOS USB interface selection, bounded command
handling, a read-only command policy, packet validation, and offline protocol
tests. The upstream license and README are retained. The upstream README
describes the general-purpose upstream tool; use this repository's root README
for the RG Rotate preview's supported workflow and limitations.

## PAC-Extractor format reference

- Upstream: [bismoy-bot/PAC-Extractor](https://github.com/bismoy-bot/PAC-Extractor)
- Pinned revision: `7d4e59b6a5ba86a7ea4e8c42d9c5f229037a6893`
- Copyright (c) 2025 Bismoy Ghosh
- License: [MIT](third_party/pac-extractor/LICENSE)
- Reference records: `third_party/pac-extractor`

The field layout documented in upstream `extractor.py` was consulted when
implementing the original PAC reader, subsequently ported to Rust. The reader
and its regression tests were independently written for this project. The upstream extraction script is not
bundled; its license and README are preserved verbatim with a pinned source
record.

## External build dependency: libusb

The native backend links against a separately installed
[libusb](https://github.com/libusb/libusb), licensed under
[LGPL-2.1-or-later](https://github.com/libusb/libusb/blob/master/COPYING).
This source repository does not bundle libusb source or binaries. Users install
the dependency separately as described in the root README.

Firmware archives, partition images, device backups, and vendor FDL loader
binaries are not included. Their licensing is separate from this project.

## Rust dependencies

Cargo dependencies and their exact versions are recorded in `Cargo.lock`. Their
upstream licenses apply independently of this repository's MIT license. Cargo
downloads these crates from crates.io; their source is not vendored here.
