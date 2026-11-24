# BCS helper — Phase 1 (link only): the Bluetooth facts, masking rules and error classification
# shared by the RFCOMM sidecar and the probe-channel script. The sidecar writes only allowlisted auth frames.
# Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
# See NOTICE in this directory for attribution and privacy rules.
#
# Standard library only, on purpose: this file must run on a fresh CachyOS/Arch box with no pip.
# Everything that touches a socket, a clock or a subprocess takes it as an argument, so the tests
# drive it with a fake socket and never need Bluetooth hardware.
#
# Phase 3G adds two opt-in behaviours, both off unless the caller asks for them: a BT_SECURITY level
# applied before connect(), and the bond precondition a --require-bond run checks first. The default
# path is byte-for-byte what every earlier phase did.
#
# The watch's address is NOT treated as a secret, but it is never printed in full. It lives only
# in the user's own config file (see load_watch_address); nothing here logs it unmasked.

from __future__ import annotations

import errno
import json
import os
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field

# Where the address lives. Outside the repository, mode 0600, written by tools/watch-address.py.
DEFAULT_CONFIG_PATH = os.path.expanduser("~/.config/aether-bcs/watch.json")

# The Huawei SDP service UUID. Reference source (constant only, no code copied):
# Gadgetbridge devices/huawei/HuaweiConstants.java:33, commit de7c2ba8d636a3dc5b750770fb3654671a4bd260.
HUAWEI_SDP_UUID = "82ff3820-8411-400c-b85a-55bdb32cf060"
# The standard Bluetooth serial-port profile UUID, for sdptool output that names the profile only.
SPP_UUID = "00001101-0000-1000-8000-00805f9b34fb"

MASKED_ADDRESS = "XX:XX:XX:XX:XX:XX"
CHANNEL_MIN = 1
CHANNEL_MAX = 30
DEFAULT_PROBE_TIMEOUT = 3.0
DEFAULT_PROBE_BUDGET = 90.0
# How long sdptool may take to answer an SDP browse. SDP is a read-only query, but it is a query
# *to the watch*, so it gets its own bound instead of riding on a connect timeout.
SDP_QUERY_TIMEOUT = 20.0
# A bonded watch can answer `Connected: no` while its ACL link wakes. Retry only that answer.
SDP_MAX_ATTEMPTS = 3
SDP_RETRY_BACKOFF = 0.25
# How long `bluetoothctl info` may take when the caller asks whether the watch is paired at all.
BOND_QUERY_TIMEOUT = 10.0

# Phase 3G (D1): an opt-in security level for the RFCOMM socket. `SOL_BLUETOOTH` and `BT_SECURITY`
# are taken from this Python build when it has them (3.14 does) and fall back to the Linux numbers
# otherwise. The optval of BT_SECURITY is `struct bt_security`, i.e. exactly two bytes — level and
# then key size — so a bare `int` would be encoded as a C int (4 bytes) and refused by the stack.
SOL_BLUETOOTH = getattr(socket, "SOL_BLUETOOTH", 274)
BT_SECURITY_OPTION = getattr(socket, "BT_SECURITY", 4)
# Linux `struct bt_power` is one byte. FORCE_ACTIVE_ON asks the controller not to enter sniff mode
# while LinkParams is pending. Kernels without this option reject it with ENOPROTOOPT, which is safe
# to ignore; all other option failures still close the socket and fail the connection.
BT_POWER_OPTION = getattr(socket, "BT_POWER", 9)
BT_POWER_FORCE_ACTIVE_ON = getattr(socket, "BT_POWER_FORCE_ACTIVE_ON", 1)
# `none` keeps every previous phase's behaviour: no security level is asked for at all.
BT_SECURITY_LEVELS = {"none": None, "low": 1, "medium": 2, "high": 3}
# The pairs a `bluetoothctl info` answer can carry. Absent means "cannot say", which a
# --require-bond run treats as a refusal rather than as a pass.
_BONDED_LINE = re.compile(r"^\s*Bonded:\s*(yes|no)\s*$", re.IGNORECASE | re.MULTILINE)

_OCTET = re.compile(r"^[0-9A-Fa-f]{2}$")
_MAC_IN_TEXT = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")
_SDTOOL_CHANNEL = re.compile(r"^\s*Channel:\s*(\d+)\s*$", re.MULTILINE)

# errnos that mean "stop, this is not a closed channel": the adapter, the permissions or the
# watch itself is in the way, and probing the remaining channels would only repeat the failure.
FATAL_CONNECT_ERRNOS = frozenset(
    value
    for value in (
        getattr(errno, "EPERM", None),
        getattr(errno, "EACCES", None),
        getattr(errno, "EBUSY", None),
        getattr(errno, "EHOSTDOWN", None),
        getattr(errno, "EHOSTUNREACH", None),
        getattr(errno, "ENETDOWN", None),
        getattr(errno, "ENETUNREACH", None),
    )
    if value is not None
)

# errno -> (stable code, plain-English remedy). The message is what the user reads, so it says
# what to do next rather than naming a constant.
_CONNECT_ERRORS = {
    errno.EBUSY: ("busy", "the Bluetooth adapter or the watch is busy; the watch is most likely still connected to your phone"),
    errno.EACCES: ("permission", "permission denied for Bluetooth sockets; check your user's access to the Bluetooth daemon"),
    errno.EPERM: ("permission", "permission denied for Bluetooth sockets; check your user's access to the Bluetooth daemon"),
    errno.ECONNREFUSED: ("refused", "the watch refused this RFCOMM channel; a channel with no service behaves this way"),
    errno.ETIMEDOUT: ("timeout", "the Bluetooth stack reported a timeout; the watch may be off, out of range, or busy"),
    errno.EHOSTDOWN: ("unreachable", "the watch did not answer; check that Bluetooth is on and the watch is awake"),
    errno.EHOSTUNREACH: ("unreachable", "the watch is out of range or not powered"),
    errno.ENETDOWN: ("unreachable", "the local Bluetooth adapter is down; check that the Bluetooth service is running"),
    errno.ENETUNREACH: ("unreachable", "the local Bluetooth adapter has no route to the watch"),
    errno.ECONNRESET: ("reset", "the watch closed the connection immediately after it was accepted"),
    errno.EPIPE: ("reset", "the connection dropped"),
    errno.ENODEV: ("unreachable", "that address is not known to this machine; pair the watch first"),
    errno.EINVAL: ("bad-config", "the channel number is out of range for RFCOMM"),
}


class BcsLinkError(Exception):
    """A link error with a stable code, a masked message and an optional errno."""

    def __init__(self, code: str, message: str, errno_value: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.errno_value = errno_value

    def to_wire(self) -> dict:
        return {
            "ok": False,
            "code": self.code,
            "error": mask_text(str(self)),
            "errno": self.errno_value,
        }


def _parts(value: object) -> list[str]:
    return str(value if value is not None else "").strip().split(":")


def is_address(value: object) -> bool:
    parts = _parts(value)
    return len(parts) == 6 and all(_OCTET.match(part) for part in parts)


def mask_address(value: object) -> str:
    """Keep the last two octets, hide the rest. Anything invalid becomes fully masked."""
    if not is_address(value):
        return MASKED_ADDRESS
    parts = _parts(value)
    return "XX:XX:XX:XX:" + parts[4].upper() + ":" + parts[5].upper()


def mask_text(text: object) -> str:
    """Mask every address inside a longer string. Idempotent: XX is not a hex octet."""
    return _MAC_IN_TEXT.sub(
        lambda match: mask_address(match.group(0)), str(text if text is not None else "")
    )


def load_watch_address(config_path: str = DEFAULT_CONFIG_PATH) -> str:
    """Read the saved address. The only file this helper ever opens under ~/.config/aether-bcs/.

    Raises BcsLinkError("no-config") when the file is absent and ("bad-config") when it does not
    hold a usable address. Neither the file contents nor any value from it is ever logged.
    """
    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        raise BcsLinkError(
            "no-config",
            "no saved watch address; run: python3 tools/watch-address.py list, then save",
        ) from None
    except (OSError, json.JSONDecodeError) as exc:
        raise BcsLinkError(
            "bad-config", f"the saved watch address could not be read ({type(exc).__name__})"
        ) from None
    address = data.get("address") if isinstance(data, dict) else None
    if not is_address(address):
        raise BcsLinkError("bad-config", "the saved watch address file has no valid address")
    return str(address)


def save_watch_address(address: str, config_path: str = DEFAULT_CONFIG_PATH) -> None:
    """Write {"address": ...} with mode 0600. Never prints or returns the address."""
    if not is_address(address):
        raise BcsLinkError("bad-config", "that is not a valid Bluetooth address")
    directory = os.path.dirname(config_path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    # Created with 0600 from the first byte, so the address is never briefly world-readable.
    descriptor = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps({"address": address}) + "\n")
    os.chmod(config_path, 0o600)


def classify_connect_error(
    exc: BaseException,
    security: str = "none",
    timeout: float | None = None,
) -> BcsLinkError:
    """Turn a socket failure into a code and a sentence the user can act on.

    Two failures can only be described honestly when the caller hands over its context:

    * a permission error while a security level was asked for is the stack refusing the *secure*
      link — almost always because the watch is not bonded — and not a broken local Bluetooth
      daemon, so it gets its own code (`security-refused`) and its own sentence;
    * a timeout is either the Bluetooth stack reporting one or this helper's own `settimeout()`
      cut. Saying which one matters: the first is evidence about the watch, the second is a
      decision we made, and blaming the watch for it sends the user the wrong way.
    """
    if isinstance(exc, BcsLinkError):
        return exc
    number = getattr(exc, "errno", None)
    if security != "none" and number in (errno.EACCES, errno.EPERM):
        return BcsLinkError(
            "security-refused",
            "the Bluetooth stack refused the secure link; the watch is probably not bonded to this computer",
            number,
        )
    if isinstance(exc, TimeoutError) and number is None:
        if timeout is None:
            return BcsLinkError("timeout", "the connection attempt timed out; the watch may be off, out of range, or busy")
        return BcsLinkError(
            "timeout",
            f"no answer within the {timeout:g}s this helper allows; the watch may be off, out of range, or busy",
        )
    if number in _CONNECT_ERRORS:
        code, message = _CONNECT_ERRORS[number]
        return BcsLinkError(code, message, number)
    if isinstance(exc, socket.timeout):
        return BcsLinkError("timeout", "the connection attempt timed out")
    if isinstance(exc, OSError) and number is None:
        return BcsLinkError("unknown", f"the Bluetooth socket failed ({type(exc).__name__})")
    return BcsLinkError("unknown", f"the Bluetooth socket failed (errno {number})", number)


def bt_security_level(name: object) -> int | None:
    """The BT_SECURITY level for a name, or None for `none`. Anything else is a refusal.

    A name outside the four is refused here rather than passed to the stack, so a typo cannot
    become a silently different link.
    """
    if isinstance(name, str):
        # `none` is the default and means "ask for nothing", which is what every earlier phase did.
        if name in BT_SECURITY_LEVELS:
            return BT_SECURITY_LEVELS[name]
    raise BcsLinkError(
        "bad-config",
        "bt_security must be one of " + ", ".join(BT_SECURITY_LEVELS),
    )


def apply_bt_security(handle, level: int) -> None:
    """Ask the stack for an authenticated/encrypted link, before connect().

    The optval is two bytes (`struct bt_security`: level, key size) sent as a buffer, because
    CPython would otherwise encode a bare int as a four-byte C int.
    """
    handle.setsockopt(SOL_BLUETOOTH, BT_SECURITY_OPTION, bytes([level, 0]))


def rfcomm_socket(timeout: float, security: str = "none") -> socket.socket:
    """A real RFCOMM socket with active link policy, timeout and optional security before connect."""
    for name in ("AF_BLUETOOTH", "BTPROTO_RFCOMM"):
        if not hasattr(socket, name):
            raise BcsLinkError("unsupported", "this Python build has no Bluetooth socket support")
    level = bt_security_level(security)
    handle = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    try:
        try:
            handle.setsockopt(SOL_BLUETOOTH, BT_POWER_OPTION, bytes([BT_POWER_FORCE_ACTIVE_ON]))
        except OSError as exc:
            if exc.errno != errno.ENOPROTOOPT:
                raise
        if level is not None:
            apply_bt_security(handle, level)
        handle.settimeout(timeout)
        return handle
    except BaseException:
        handle.close()
        raise


def connect_channel(
    address: str,
    channel: int,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
    factory=rfcomm_socket,
    security: str = "none",
):
    """Connect to one RFCOMM channel and hand back the open socket. Sends nothing.

    The caller owns the socket and must close it. Nothing is written by this function: a
    Bluetooth connect performs SDP and link setup, which is not application data.

    `security` is passed to the socket factory, and a factory that does not take it is never
    asked for it: the default `none` call is unchanged, which is what keeps every earlier phase's
    behaviour identical.
    """
    if not isinstance(channel, int) or not CHANNEL_MIN <= channel <= CHANNEL_MAX:
        raise BcsLinkError("bad-config", f"channel must be {CHANNEL_MIN}-{CHANNEL_MAX}")
    level = bt_security_level(security)
    handle = factory(timeout, security) if level is not None else factory(timeout)
    try:
        handle.connect((address, channel))
    except BaseException as exc:  # noqa: BLE001 - every socket failure becomes a BcsLinkError
        try:
            handle.close()
        except Exception:  # noqa: BLE001 - closing a failed socket must not mask the real error
            pass
        raise classify_connect_error(exc, security=security, timeout=timeout) from None
    return handle


@dataclass
class SdpResult:
    """What SDP could tell us. `method` says which tool answered, so the answer is auditable."""

    method: str
    channel: int | None
    detail: str
    saw_huawei_uuid: bool = False
    saw_spp_uuid: bool = False
    # Which record the returned channel came from. `matched_uuid` means the record itself carried
    # the Huawei service UUID; `matched_serial` means it carried the serial-port profile name or
    # UUID. A channel with neither is a *guess from the dump*, not a resolved channel, and the
    # caller refuses it: that is the difference between "SDP named it" and "a probe found it".
    matched_uuid: bool = False
    matched_serial: bool = False

    @property
    def confirmed(self) -> bool:
        """True when the record behind `channel` named the Huawei UUID or the serial-port profile."""
        return self.matched_uuid or self.matched_serial


# Lines that mark an SDP record as the serial-port service: the profile name or its short UUID.
# UUID128 values are matched separately so case, omitted dashes, and Bluetooth byte order all work.
_SERIAL_MARKERS = ("serial port", "0x1101")
_UUID128_TEXT = re.compile(
    r"(?i)(?<![0-9a-f])(?:0x)?("
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32}"
    r")(?![0-9a-f])"
)


def _uuid_forms(uuid: str) -> frozenset[str]:
    """Canonical, full Bluetooth-little-endian, and mixed-endian forms of one UUID128."""
    compact = uuid.replace("-", "").lower()
    mixed = compact[6:8] + compact[4:6] + compact[2:4] + compact[0:2]
    mixed += compact[10:12] + compact[8:10] + compact[14:16] + compact[12:14] + compact[16:]
    reversed_bytes = bytes.fromhex(compact)[::-1].hex()
    return frozenset((compact, reversed_bytes, mixed))


def _record_has_uuid(record: str, uuid: str) -> bool:
    forms = _uuid_forms(uuid)
    return any(match.group(1).replace("-", "").lower() in forms for match in _UUID128_TEXT.finditer(record))


_RECORD_SPLIT = re.compile(r"(?=^\s*(?:Service Name|Service RecHandle):)", re.MULTILINE)


def serial_channel_record(text: str) -> tuple[int | None, str]:
    """The serial record's RFCOMM channel and the evidence behind it.

    Returns `(channel, marker)` where marker is:

    * `"huawei"` — the record carried the Huawei service UUID, the strongest evidence there is;
    * `"serial"` — the record carried the serial-port profile name, short form or UUID;
    * `"only"` — no marker at all, but the dump holds exactly one channel, so it is the only record
      that can be meant (a guess from the dump, not a resolved channel);
    * `""` — no channel, or several channels and nothing to choose between them: never guessed, the
      caller probes instead.
    """
    records = [block for block in _RECORD_SPLIT.split(text or "") if block.strip()]
    channels = [int(match.group(1)) for match in _SDTOOL_CHANNEL.finditer(text or "")]
    for block in records:
        match = _SDTOOL_CHANNEL.search(block)
        if not match:
            continue
        lowered = block.lower()
        if _record_has_uuid(block, HUAWEI_SDP_UUID):
            return int(match.group(1)), "huawei"
        if _record_has_uuid(block, SPP_UUID) or any(marker in lowered for marker in _SERIAL_MARKERS):
            return int(match.group(1)), "serial"
    if len(channels) == 1:
        return channels[0], "only"
    return None, ""


def channel_from_sdptool(text: str) -> int | None:
    """The RFCOMM channel of the serial record in `sdptool browse` output, or None.

    A dump with exactly one channel overall is accepted even without a serial marker, because
    that is the only record that can be meant. Several channels and no marker is not guessed:
    the caller probes instead. `serial_channel_record` is the same parse with the evidence
    attached, which is what a connect target has to be checked against.
    """
    return serial_channel_record(text)[0]


def lookup_sdp(
    address: str,
    which=shutil.which,
    runner=subprocess.run,
    timeout: float = SDP_QUERY_TIMEOUT,
    sleep=time.sleep,
) -> SdpResult:
    """Ask BlueZ for channel and evidence, retrying only a sleeping bonded watch's ACL link."""
    if which("sdptool"):
        for attempt in range(SDP_MAX_ATTEMPTS):
            try:
                completed = runner(["sdptool", "browse", address], capture_output=True, text=True, timeout=timeout)
            except subprocess.TimeoutExpired:
                return SdpResult("sdptool", None, f"sdptool did not answer within {timeout:.0f}s")
            except OSError as exc:
                return SdpResult("sdptool", None, f"sdptool could not run ({type(exc).__name__})")
            text = f"{completed.stdout or ''}{completed.stderr or ''}"
            channel, marker = serial_channel_record(text)
            if channel is not None:
                evidence = {
                    "huawei": "the record carrying the Huawei service UUID",
                    "serial": "the serial-port record",
                    "only": "the only channel in the answer",
                }.get(marker, "a record")
                return SdpResult(
                    "sdptool",
                    channel,
                    f"sdptool named the RFCOMM channel of {evidence}",
                    saw_huawei_uuid=_record_has_uuid(text, HUAWEI_SDP_UUID),
                    saw_spp_uuid=("1101" in text.lower().replace("-", "")) or ("serial port" in text.lower()),
                    matched_uuid=marker == "huawei",
                    matched_serial=marker == "serial",
                )
            # A bonded watch can report this while its ACL link wakes. Nothing else is retried,
            # and retries never weaken the evidence gate or turn a probed channel into a target.
            if not re.search(r"Connected:\s*no\b", text, re.IGNORECASE):
                return SdpResult(
                    "sdptool", None, "sdptool ran, but no serial-port record with a channel was in the answer"
                )
            if attempt + 1 < SDP_MAX_ATTEMPTS:
                sleep(SDP_RETRY_BACKOFF * (attempt + 1))
        return SdpResult("sdptool", None, "the ACL link stayed asleep after three SDP attempts")

    if which("bluetoothctl"):
        try:
            completed = runner(["bluetoothctl", "info", address], capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return SdpResult("bluetoothctl", None, f"bluetoothctl did not answer ({type(exc).__name__})")
        text = f"{completed.stdout or ''}{completed.stderr or ''}"
        flattened = text.lower().replace("-", "")
        return SdpResult(
            "bluetoothctl",
            None,
            "no SDP browser on this machine (sdptool is not installed); bluetoothctl and D-Bus expose the "
            "device's advertised UUIDs only, never the RFCOMM channel",
            saw_huawei_uuid=HUAWEI_SDP_UUID.replace("-", "") in flattened,
            saw_spp_uuid=("1101" in flattened) or ("serial port" in flattened),
        )

    return SdpResult("unavailable", None, "neither sdptool nor bluetoothctl was found in PATH")


def verify_sdp_channel(sdp: SdpResult, expected: int | None) -> tuple[bool, str, str]:
    """Decide whether an SDP answer may become a connect target: (ok, code, message).

    The channel is only ever taken from SDP. A probe result is never a substitute, so every
    refusal here happens before any socket exists. `expected` is the saved channel when the caller
    has one; SDP has to agree with it, and a disagreement is a refusal rather than a silent
    re-target, because the saved value came from a probe.
    """
    if sdp.channel is None:
        if sdp.method == "unavailable":
            return (
                False,
                "sdp-unavailable",
                "SDP could not be read: neither sdptool nor bluetoothctl is on PATH, so the watch's "
                "RFCOMM channel cannot be resolved. Install bluez-deprecated-tools (sdptool), fix "
                "PATH, then run again. No link was opened.",
            )
        return (
            False,
            "sdp-no-channel",
            f"SDP could not name the serial channel ({sdp.method}: {sdp.detail}). No link was "
            "opened, and a channel found by probing is never used instead.",
        )
    if not sdp.confirmed:
        return (
            False,
            "sdp-unconfirmed",
            f"SDP reported channel {sdp.channel}, but the record carries neither the Huawei service "
            f"UUID {HUAWEI_SDP_UUID} nor a serial-port profile, so that channel is not proven to be "
            "the watch's. Check it with `sdptool browse <address>`, then run again. No link was "
            "opened, and a channel found by probing is never used instead.",
        )
    if expected is not None and sdp.channel != expected:
        return (
            False,
            "sdp-disagreement",
            f"SDP says the Huawei service is on channel {sdp.channel}, but the saved channel is "
            f"{expected}. Refusing to connect: the saved channel came from a probe, and SDP "
            f"disagrees with it. Keep the SDP answer, and run again with --channel {sdp.channel} "
            "once you have seen the same number yourself. No link was opened.",
        )
    return True, "", ""


@dataclass
class BondResult:
    """Whether this machine is paired with the watch. `bonded` is None when the answer is absent."""

    method: str
    bonded: bool | None
    detail: str


def probe_bond(
    address: str,
    which=shutil.which,
    runner=subprocess.run,
    timeout: float = BOND_QUERY_TIMEOUT,
) -> BondResult:
    """Ask BlueZ whether this machine is paired with the watch. Never raises.

    This is the same `bluetoothctl info` call the SDP path already makes, read for a different
    line: `Bonded: yes`. It is a *precondition check* — nothing here pairs, connects or writes,
    and a missing tool or a missing line is reported as "cannot say" rather than as a pass.
    """
    if not which("bluetoothctl"):
        return BondResult(
            "unavailable",
            None,
            "bluetoothctl is not on PATH, so this helper cannot check whether the watch is paired",
        )
    try:
        completed = runner(["bluetoothctl", "info", address], capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return BondResult("bluetoothctl", None, f"bluetoothctl did not answer ({type(exc).__name__})")
    text = f"{completed.stdout or ''}{completed.stderr or ''}"
    match = _BONDED_LINE.search(text)
    if match is None:
        return BondResult(
            "bluetoothctl",
            None,
            "bluetoothctl's answer carried no \"Bonded:\" line, so the pairing state is unknown",
        )
    bonded = match.group(1).lower() == "yes"
    return BondResult(
        "bluetoothctl",
        bonded,
        "bluetoothctl reports the watch is paired with this computer"
        if bonded
        else "bluetoothctl reports the watch is not paired with this computer",
    )


def verify_bond(result: BondResult) -> tuple[bool, str, str]:
    """Decide whether a --require-bond run may open a socket: (ok, code, message).

    Only a positive `Bonded: yes` passes. "Not paired", a missing line and a missing tool are all
    refusals: the option exists to make the precondition visible, so an unknown state cannot be
    treated as satisfied. Nothing here pairs the watch — pairing is the user's job, done with
    bluetoothctl or the desktop's own settings.
    """
    if result.bonded is True:
        return True, "", ""
    if result.bonded is False:
        return (
            False,
            "not-bonded",
            "this computer is not paired with the watch, and --require-bond asked for a paired watch. "
            "Pair it first with `bluetoothctl pair <address>` (or your desktop's Bluetooth settings), "
            "then run again: this helper never pairs. No link was opened.",
        )
    return (
        False,
        "not-bonded",
        f"the pairing state could not be verified ({result.method}: {result.detail}), and "
        "--require-bond refuses to open a link it cannot vouch for. Check with "
        "`bluetoothctl info <address>` and pair the watch if it is missing. No link was opened.",
    )


@dataclass
class ProbeResult:
    channel: int
    outcome: str  # "accepted" | "refused"
    code: str | None = None
    detail: str = ""


@dataclass
class ProbeOutcome:
    """One pass over the channels. `aborted_reason` means probing stopped on purpose."""

    results: list[ProbeResult] = field(default_factory=list)
    accepted: int | None = None
    aborted_reason: str | None = None

    def failure_tally(self) -> str:
        counts: dict[str, int] = {}
        for result in self.results:
            if result.outcome == "refused":
                counts[result.code or "unknown"] = counts.get(result.code or "unknown", 0) + 1
        return ", ".join(f"{code}={count}" for code, count in sorted(counts.items()))


# Codes that say "the link itself is not available", where trying the next channel is pointless.
_FATAL_PROBE_CODES = frozenset(
    {"busy", "permission", "unreachable", "unsupported", "bad-config", "security-refused", "not-bonded"}
)


def probe_channels(
    address: str,
    channels=None,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
    factory=rfcomm_socket,
    budget: float = DEFAULT_PROBE_BUDGET,
    clock=time.monotonic,
    on_result=None,
) -> ProbeOutcome:
    """Try each channel once: connect, close immediately, report. Not one byte is written.

    Stops at the first channel that accepts, because the watch has a single serial service.
    Stops early when the failure is about the link rather than the channel, and never retries a
    channel, so a refused watch is not hammered.
    """
    wanted = list(range(CHANNEL_MIN, CHANNEL_MAX + 1)) if channels is None else list(channels)
    outcome = ProbeOutcome()
    started = clock()
    for channel in wanted:
        if clock() - started > budget:
            outcome.aborted_reason = f"stopped after {budget:.0f}s so one run cannot hang indefinitely"
            break
        try:
            handle = connect_channel(address, channel, timeout, factory)
        except BcsLinkError as exc:
            outcome.results.append(ProbeResult(channel, "refused", exc.code, mask_text(str(exc))))
            if on_result:
                on_result(outcome.results[-1])
            if exc.code in _FATAL_PROBE_CODES or exc.errno_value in FATAL_CONNECT_ERRNOS:
                outcome.aborted_reason = mask_text(str(exc))
                break
            continue
        # Accepted: close it at once. Nothing was written and nothing is read.
        try:
            handle.close()
        except Exception:  # noqa: BLE001 - a failed close must not hide the accepted channel
            pass
        outcome.results.append(ProbeResult(channel, "accepted", None, "connected, then closed immediately"))
        if on_result:
            on_result(outcome.results[-1])
        outcome.accepted = channel
        break
    return outcome


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def read_loop(handle, emit, stop, chunk: int = 4096, emit_hex: bool = False) -> None:
    """Report arriving bytes as a count and a time. Content is omitted unless emit_hex is on.

    Idle timeouts are normal and just continue. A closed socket, or any other socket error, ends
    the loop with one event. The caller owns `handle` and closes it.
    """
    while not stop.is_set():
        try:
            data = handle.recv(chunk)
        except (TimeoutError, socket.timeout):
            continue
        except OSError as exc:
            failure = classify_connect_error(exc)
            emit(
                {
                    "event": "error",
                    "error": mask_text(str(failure)),
                    "code": failure.code,
                    "errno": failure.errno_value,
                }
            )
            return
        if not data:
            emit({"event": "closed", "at": now_iso(), "reason": "the watch closed the link"})
            return
        event = {"event": "data", "bytes": len(data), "at": now_iso()}
        if emit_hex:
            event["hex"] = bytes(data).hex()
        emit(event)


def format_probe_report(
    masked_address: str,
    sdp: SdpResult,
    outcome: ProbeOutcome,
    timeout: float,
    channel_spec: str,
) -> list[str]:
    """The probe's whole output: masked address, the SDP answer, and the channel. No errno noise."""
    lines = [f"masked_address: {masked_address}"]
    if sdp.channel is not None:
        lines.append(f"sdp: {sdp.method} reported channel {sdp.channel}")
    else:
        lines.append(f"sdp: {sdp.method} -> no channel ({sdp.detail})")
        if sdp.method == "bluetoothctl":
            lines.append(
                "sdp_evidence: huawei_uuid=%s serial_port=%s"
                % ("yes" if sdp.saw_huawei_uuid else "no", "yes" if sdp.saw_spp_uuid else "no")
            )
    # Whether SDP actually named the channel. A probed channel is a guess, and the live bind
    # re-resolves the channel through SDP before it connects, so the probe says so out loud.
    lines.append(f"sdp_confirmed: {'yes' if sdp.confirmed else 'no'}")
    lines.append(f"probed: {channel_spec} (timeout {timeout:.1f}s each, first accept wins)")
    if outcome.accepted is not None:
        lines.append(f"channel: {outcome.accepted}")
        lines.append("result: accepted")
    else:
        lines.append("channel: none")
        lines.append("result: refused")
    tally = outcome.failure_tally()
    if tally:
        lines.append(f"failure_codes: {tally}")
    if outcome.aborted_reason:
        lines.append(f"stopped_early: {outcome.aborted_reason}")
    return lines