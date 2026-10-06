#!/bin/sh
set -eu
task_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
command -v pkg-config >/dev/null 2>&1 || { echo 'pkg-config is required (brew install pkg-config libusb)' >&2; exit 1; }
pkg-config --exists libusb-1.0 || { echo 'libusb is required (brew install libusb)' >&2; exit 1; }
mkdir -p "$task_root/build"
cc -O2 -Wall -Wextra -std=c99 -DUSE_LIBUSB=1 \
  $(pkg-config --cflags libusb-1.0) \
  "$task_root/vendor/spreadtrum_flash/spd_dump.c" \
  -o "$task_root/build/spd_dump" $(pkg-config --libs libusb-1.0)
echo "Built $task_root/build/spd_dump"
