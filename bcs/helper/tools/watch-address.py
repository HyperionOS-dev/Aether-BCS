#!/usr/bin/env python3
# BCS helper — Phase 1 (link only): list the Bluetooth devices this machine knows, and save the
# watch's address where the sidecar can read it. Writes no bytes to the watch.
# Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
# See ../NOTICE for attribution and privacy rules.
#
#   python3 tools/watch-address.py list     # masked addresses, so the output is safe to paste
#   python3 tools/watch-address.py save     # hidden prompt, then mode 0600 outside the repository
#   python3 tools/watch-address.py show     # what is saved now, masked
#
# The address is asked for on a hidden prompt rather than as an argument, so it never lands in
# a shell history, a process list, or a chat log. It is never printed in full, and `list` shows
# every device masked: the last two octets are enough to tell two watches apart.

from __future__ import annotations

import argparse
import getpass
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
# The Bluetooth facts live in sidecar/, next to the helper rather than under tools/.
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, os.pardir, "sidecar")))

import bcs_bt  # noqa: E402 - the path above has to be set up first

# Names that suggest the watch, so the right line can be picked out of a busy cache.
_WATCH_HINTS = ("watch", "huawei", "vili", "gt ")


def _bluetoothctl_devices(runner=subprocess.run) -> tuple[list[tuple[str, str]], str | None]:
    """[(masked address, name)] from BlueZ's cache, plus a note when the tool could not be used."""
    try:
        completed = runner(["bluetoothctl", "devices"], capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return [], "bluetoothctl was not found: install bluez or run `bluetoothctl devices` yourself"
    except subprocess.TimeoutExpired:
        return [], "bluetoothctl did not answer within 15s"
    except OSError as exc:
        return [], f"bluetoothctl could not run ({type(exc).__name__})"
    text = f"{completed.stdout or ''}{completed.stderr or ''}"
    devices: list[tuple[str, str]] = []
    for line in text.splitlines():
        parts = line.strip()
        if not parts.startswith("Device "):
            continue
        rest = parts[len("Device ") :].strip()
        address, _, name = rest.partition(" ")
        if not bcs_bt.is_address(address):
            continue
        devices.append((bcs_bt.mask_address(address), name.strip() or "(no name)"))
    return devices, None


def cmd_list(args, out=print) -> int:
    devices, note = _bluetoothctl_devices()
    if note:
        out(f"note: {bcs_bt.mask_text(note)}")
    if not devices:
        out("no devices in the BlueZ cache. Run `bluetoothctl scan on` in another terminal with the")
        out("watch awake and its Bluetooth visible, then run this again. Pair the watch if you have not.")
        return 1
    out(f"{len(devices)} device(s) known to this machine (addresses masked):")
    for masked, name in sorted(devices, key=lambda item: item[1].lower()):
        hint = "  <- looks like the watch" if any(word in name.lower() for word in _WATCH_HINTS) else ""
        out(f"  {masked}  {name}{hint}")
    out("")
    out("Check the name against your watch's own Bluetooth settings, then run:")
    out("  python3 tools/watch-address.py save      # you will type the full address, hidden")
    return 0



def cmd_show(args, out=print) -> int:
    out(f"config file: {args.config}")
    try:
        address = bcs_bt.load_watch_address(args.config)
    except bcs_bt.BcsLinkError as failure:
        out(f"watch address: not saved yet ({bcs_bt.mask_text(str(failure))})")
        return 1
    try:
        mode = oct(os.stat(args.config).st_mode & 0o777)
    except OSError:
        mode = "unknown"
    out(f"watch address: {bcs_bt.mask_address(address)} (mode {mode})")
    return 0


def cmd_save(args, out=print, ask=getpass.getpass) -> int:
    out("Type the watch's Bluetooth address (it is hidden while you type, so it stays out of")
    out("your shell history). You can read it on the watch under Settings > About/Bluetooth.")
    try:
        typed = ask("watch address (hidden): ")
    except (EOFError, KeyboardInterrupt):
        out("nothing was saved.")
        return 1
    address = (typed or "").strip()
    if not bcs_bt.is_address(address):
        out("that is not a six-octet address like AA:BB:CC:DD:EE:FF, so nothing was saved.")
        return 1
    try:
        bcs_bt.save_watch_address(address, args.config)
    except bcs_bt.BcsLinkError as failure:
        out(f"could not save it: {bcs_bt.mask_text(str(failure))}")
        return 1
    out(f"saved {bcs_bt.mask_address(address)} to {args.config} with mode 0600.")
    out("That file is outside the repository and is never committed; keep it that way.")

    devices, note = _bluetoothctl_devices()
    if note:
        out(f"note: {bcs_bt.mask_text(note)}")
    elif devices and bcs_bt.mask_address(address) not in [masked for masked, _ in devices]:
        out("note: this address is not in the BlueZ cache. If the watch has never been paired,")
        out("      pair it first: `bluetoothctl` then `scan on`, `pair <address>`, `trust <address>`.")
    out("next: python3 probe-channel")
    return 0


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="watch-address.py",
        description="Show the devices this machine knows, and save the watch's address for the sidecar.",
    )
    parser.add_argument("--config", default=bcs_bt.DEFAULT_CONFIG_PATH, help="where the address is saved")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list", help="list known devices, masked (needs bluetoothctl)")
    sub.add_parser("save", help="prompt for the watch address, hidden, and save it as mode 0600")
    sub.add_parser("show", help="show whether an address is saved, masked")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.command == "list":
        return cmd_list(args)
    if args.command == "save":
        return cmd_save(args)
    if args.command == "show":
        return cmd_show(args)
    parse_args(["--help"])
    return 2


if __name__ == "__main__":
    sys.exit(main())
