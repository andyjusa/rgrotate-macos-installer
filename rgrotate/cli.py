"""Command-line entry point with an offline default and explicit device actions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .pac import PacError, PacFile
from .plan import PlanError, build_plan, require_flash_ready


def _wait_seconds(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("wait must be an integer") from exc
    if not 1 <= seconds <= 30:
        raise argparse.ArgumentTypeError("wait must be between 1 and 30 seconds")
    return seconds


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rgrotate",
        description="Inspect or probe an RG Rotate PAC, or install pinned Full firmware on a compatible layout.",
        epilog="Examples: rgrotate plan firmware.pac; rgrotate probe firmware.pac --out probe-report --backend build/spd_dump",
    )
    parser.add_argument("pac", type=Path, help="official RG Rotate PAC file")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--plan", action="store_true", help="offline plan (the default)")
    action.add_argument("--probe", action="store_true", help="load official FDLs into RAM and perform read-only checks")
    action.add_argument("--flash", action="store_true", help="explicitly request firmware writes")
    action.add_argument("--dump-xml", action="store_true", help="print PAC XML without opening USB")
    action.add_argument("--dump-firmware", action="store_true", help="request a read-only dump (not yet implemented)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--full-flash", action="store_true", help="explicitly acknowledge the requested full-flash mode")
    mode.add_argument("--preserve-layout", action="store_true", help="request keeping the current partition table")
    parser.add_argument("--wipe-data", action="store_true", help="authorize Recovery factory reset after verified Full installation")
    parser.add_argument("--backend", type=Path, help="path to the audited spd_dump executable")
    parser.add_argument("--out", type=Path, help="new private directory for results and full readback")
    parser.add_argument("--wait", type=_wait_seconds, default=30, help="USB discovery timeout, 1–30 seconds")
    parser.add_argument("--output-json", type=Path, help="also save the report to a new file; existing files are refused")
    return parser


def _normalize_command(argv: list[str]) -> tuple[list[str], str | None]:
    if argv and argv[0] in {"plan", "probe", "flash", "dump-xml", "dump-firmware"}:
        command = argv[0]
        # 'flash' is an action name, not by itself permission to write. Require
        # the separate --flash marker so a future executor cannot be triggered
        # by an accidentally reused command line.
        if command == "flash":
            return argv[1:], command
        return ["--" + command, *argv[1:]], command
    return argv, None


def _report(value: dict, path: Path | None) -> None:
    text = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if path is not None:
        with path.open("x", encoding="utf-8") as stream:
            stream.write(text)
    sys.stdout.write(text)


def main(argv: list[str] | None = None) -> int:
    argv, command = _normalize_command(list(sys.argv[1:] if argv is None else argv))
    parser = make_parser()
    args = parser.parse_args(argv)
    if command == "flash" and not args.flash:
        parser.error("flash requires a separate --flash marker and an explicit mode")
    if args.flash and not (args.full_flash or args.preserve_layout):
        parser.error("--flash requires --full-flash or --preserve-layout")
    if (args.full_flash or args.preserve_layout) and not args.flash:
        parser.error("flash mode options require --flash")
    if args.wipe_data and not (args.flash and args.preserve_layout):
        parser.error("--wipe-data requires --flash --preserve-layout")
    if args.flash and args.preserve_layout and not args.wipe_data:
        parser.error("Full installation requires --wipe-data; preserving old user data is unsupported")
    if args.probe and (args.backend is None or args.out is None):
        parser.error("--probe requires --backend and --out")
    if args.flash and args.preserve_layout and (args.backend is None or args.out is None):
        parser.error("--flash --preserve-layout requires --backend and --out")
    if not (args.probe or (args.flash and args.preserve_layout)) and (args.backend is not None or args.out is not None):
        parser.error("--backend and --out require --probe or --flash --preserve-layout")
    if args.output_json is not None and args.output_json.exists():
        parser.error("--output-json must name a new file")
    try:
        pac = PacFile(args.pac)
        plan = build_plan(pac)
        if args.dump_xml:
            if args.output_json:
                raise PlanError("--output-json cannot be combined with --dump-xml")
            sys.stdout.write(pac.xml_text)
            if not pac.xml_text.endswith("\n"):
                sys.stdout.write("\n")
            return 0
        if args.flash:
            if args.full_flash:
                require_flash_ready(plan)
                raise PlanError("generic full-PAC execution is not implemented")
            from .install import install

            result = install(pac, args.out, args.backend, args.wait)
            _report(result, args.output_json)
            return 0
        if args.dump_firmware:
            raise PlanError("firmware dump is not implemented; no USB or storage write was attempted")
        if args.probe:
            # Lazy import is intentional: plan, malformed commands, and blocked
            # write requests must not even initialize the USB/backend module.
            from .transport import probe

            result = probe(pac, args.out, args.backend, args.wait)
            if not isinstance(result, dict):
                raise PlanError("probe backend returned an invalid report")
            _report(result, args.output_json)
        else:
            _report(plan, args.output_json)
        return 0
    except (PacError, PlanError, OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
