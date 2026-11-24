#!/usr/bin/env python3
# BCS helper — Phase 3C: the RFCOMM sidecar. It reads counts and writes only allowlisted frames.
# Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
# See ../NOTICE for attribution and privacy rules.
#
# One JSON object per line on stdin (commands) and stdout (responses and events); human
# diagnostics go to stderr, masked. The address never arrives as an argument — the sidecar reads
# it from the user's own config file, so it cannot appear in a process list or shell history.
#
# Commands:  {"id":1,"cmd":"ping"}
#            {"id":2,"cmd":"resolve_channel","uuid":"82ff...","expect_channel":18}
#                                                       -> the channel SDP names, or a coded refusal
#            {"id":3,"cmd":"connect","channel":15,"timeout_ms":10000,
#             "bt_security":"medium","require_bond":true}
#                       -> refused with channel-unverified unless resolve_channel named that same
#                          channel in this session: a channel found by probing is never connected to
#                          bt_security (default "none") asks the stack for that level before connect();
#                          require_bond (default off) refuses with not-bonded unless bluetoothctl
#                          reports "Bonded: yes" for the watch, and that check runs before any socket
#                          exists. Neither option ever pairs a watch.
#            {"id":4,"cmd":"write","hex":"..."}       -> allowlisted auth frames only
#            {"id":5,"cmd":"open_aux","channel":16}      -> refused: Phase 4
#            {"id":6,"cmd":"close"}
# Events:    {"event":"data","bytes":37,"at":"...","hex":"..."}   (hex only with --emit-hex)
#            {"event":"closed","at":"...","reason":"..."}
#            {"event":"error","error":"...","code":"...","errno":null}

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading

try:  # imported as part of the package (tests, python3 -m sidecar.rfcomm_sidecar)
    from . import bcs_bt
except ImportError:  # run as a plain file, which is how the TypeScript side starts it
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import bcs_bt  # type: ignore[no-redef]

VERSION = "bcs-helper-phase3g"
DEFAULT_SOCKET_TIMEOUT = 1.0
DEFAULT_CONNECT_TIMEOUT = 10.0
MAX_CONNECT_TIMEOUT = 30.0
# Phase 3G: both of these are off unless the caller asks, so today's links are unchanged.
DEFAULT_BT_SECURITY = "none"
MAX_WRITE_BYTES = 1024
MAX_WRITES_PER_CONNECTION = 64
MAX_TOTAL_WRITE_BYTES = 16_384
# What this process can do, as advertised by "ping". The driver requires "write" and "resolve":
# resolved means the channel came from SDP in this session rather than from a probe.
CAPABILITIES = ("connect", "write", "resolve")
# How long sdptool may take before the resolve answer becomes sdp-no-channel.
SDP_TIMEOUT = bcs_bt.SDP_QUERY_TIMEOUT
WRITE_ALLOWLIST = frozenset(
    {
        (0x01, 0x01),
        (0x01, 0x16),
        (0x01, 0x33),
        (0x01, 0x2C),
        (0x01, 0x28),
        # Service 0x1A: the account pairs. Command 0x05 is what Gadgetbridge queues after a finished
        # HiChain bind (HuaweiSupportProvider.java:787); command 0x01 is the legacy pair upstream
        # still defines (packets/AccountRelated.java:23, :26, :53). The helper never sends one yet —
        # an account frame has to be encrypted and that envelope is not implemented — but the gate
        # has to allow the frame it builds, and the drift test keeps this set in step with it.
        (0x1A, 0x01),
        (0x1A, 0x05),
    }
)


class Emitter:
    """Serialised, masked writes of protocol lines. Diagnostics never go through here."""

    def __init__(self, stream) -> None:
        self._stream = stream
        self._lock = threading.Lock()

    def send(self, message: dict) -> None:
        # Blanket mask: no line can leave this process carrying an unmasked address.
        line = bcs_bt.mask_text(json.dumps(message))
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()


class Sidecar:
    """The protocol handler. Everything it touches is injected, so tests need no sockets."""

    def __init__(
        self,
        emitter: Emitter,
        config_path: str = bcs_bt.DEFAULT_CONFIG_PATH,
        emit_hex: bool = False,
        socket_timeout: float = DEFAULT_SOCKET_TIMEOUT,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        bt_security: str = DEFAULT_BT_SECURITY,
        require_bond: bool = False,
        address_loader=bcs_bt.load_watch_address,
        connect=bcs_bt.connect_channel,
        reader=bcs_bt.read_loop,
        sdp_lookup=bcs_bt.lookup_sdp,
        bond_probe=bcs_bt.probe_bond,
    ) -> None:
        self._emitter = emitter
        self._config_path = config_path
        self._emit_hex = emit_hex
        self._socket_timeout = socket_timeout
        self._connect_timeout = connect_timeout
        # The CLI defaults for the two opt-in link options. A connect command may name its own
        # bt_security / require_bond; neither is ever applied without being asked for.
        self._bt_security = bt_security
        self._require_bond = require_bond
        self._address_loader = address_loader
        self._connect = connect
        self._reader = reader
        self._sdp_lookup = sdp_lookup
        self._bond_probe = bond_probe
        self._handle = None
        self._channel: int | None = None
        # The channel SDP named in this session. connect refuses anything else, so a probe result
        # cannot become a connect target even if the caller asks for one.
        self._verified_channel: int | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._closed = False
        self._write_count = 0
        self._write_bytes = 0
        self._slice_pair: tuple[int, int] | None = None
        self._next_slice_flag: int | None = None

    @property
    def is_connected(self) -> bool:
        return self._handle is not None

    def emit_event(self, event: dict) -> None:
        """Stamp the open channel on every event, so a data count says where it arrived."""
        if "channel" not in event and self._channel is not None:
            event["channel"] = self._channel
        self._emitter.send(event)

    def handle_command(self, command: dict) -> dict:
        """Dispatch one command. Always returns the response to write; never raises."""
        ident = command.get("id")
        name = command.get("cmd")
        try:
            if name == "ping":
                return {"id": ident, "ok": True, "version": VERSION, "capabilities": list(CAPABILITIES)}
            if name == "resolve_channel":
                return self._resolve_command(ident, command)
            if name == "connect":
                return self._connect_command(ident, command)
            if name == "write":
                return self._write_command(ident, command)
            if name == "open_aux":
                raise bcs_bt.BcsLinkError(
                    "unsupported",
                    "the dual (aux) channel is Phase 4: service 0x01 command 0x3C is not implemented, "
                    "and Phase 1 opens a single socket",
                )
            if name == "close":
                self._shutdown("closed by the caller")
                return {"id": ident, "ok": True}
            raise bcs_bt.BcsLinkError("protocol", f"unknown command {name!r}")
        except bcs_bt.BcsLinkError as failure:
            response = failure.to_wire()
            response["id"] = ident
            return response
        except Exception as exc:  # noqa: BLE001 - the pipe must survive any surprise
            return {
                "id": ident,
                "ok": False,
                "code": "unknown",
                "error": bcs_bt.mask_text(f"the sidecar failed: {type(exc).__name__}"),
                "errno": None,
            }

    def _security_for(self, command: dict) -> str:
        """The BT_SECURITY name for this connect: the command's own, else the CLI default.

        Validated with `bcs_bt.bt_security_level`, so an unknown name is a bad-config refusal here
        and never reaches the stack.
        """
        requested = command.get("bt_security", self._bt_security)
        bcs_bt.bt_security_level(requested)
        return requested

    def _require_bond_for(self, command: dict) -> bool:
        """Whether this connect must see a paired watch. A non-boolean field is a refusal."""
        requested = command.get("require_bond", self._require_bond)
        if not isinstance(requested, bool):
            raise bcs_bt.BcsLinkError("bad-config", "require_bond must be true or false")
        return requested

    def _connect_command(self, ident, command: dict) -> dict:
        if self.is_connected:
            raise bcs_bt.BcsLinkError("already-open", "the link is already open")
        channel = command.get("channel")
        if not isinstance(channel, int) or not bcs_bt.CHANNEL_MIN <= channel <= bcs_bt.CHANNEL_MAX:
            raise bcs_bt.BcsLinkError(
                "bad-config", f"channel must be {bcs_bt.CHANNEL_MIN}-{bcs_bt.CHANNEL_MAX}"
            )
        # The channel has to be the one SDP named in this session. A probed channel, a remembered
        # number or a typo stops here, before any socket exists.
        if self._verified_channel is None:
            raise bcs_bt.BcsLinkError(
                "channel-unverified",
                "no channel has been resolved through SDP in this session; ask for "
                "resolve_channel first. A channel found by probing is never connected to.",
            )
        if channel != self._verified_channel:
            raise bcs_bt.BcsLinkError(
                "channel-unverified",
                f"channel {channel} is not the channel SDP named ({self._verified_channel}); "
                "refusing to connect. A channel found by probing is never connected to.",
            )
        timeout = self._connect_timeout
        requested_ms = command.get("timeout_ms")
        if isinstance(requested_ms, (int, float)) and requested_ms > 0:
            timeout = min(max(requested_ms / 1000.0, 1.0), MAX_CONNECT_TIMEOUT)
        # Both link options are resolved and validated here, still before any socket exists, so a
        # typo cannot reach the stack and a refusal cannot leave anything open behind it.
        security = self._security_for(command)
        require_bond = self._require_bond_for(command)
        address = self._address_loader(self._config_path)
        # The bond precondition: a precondition, never a pairing feature. Only a positive
        # "Bonded: yes" passes, and the refusal happens before the socket is created.
        if require_bond:
            ok, code, message = bcs_bt.verify_bond(self._bond_probe(address))
            if not ok:
                raise bcs_bt.BcsLinkError(code, message)
        handle = self._connect(address, channel, timeout, security=security)
        # Idle reads are normal, so the socket gets a short read timeout rather than a long one.
        try:
            handle.settimeout(self._socket_timeout)
        except OSError:
            pass
        self._handle = handle
        self._channel = channel
        self._closed = False
        self._write_count = 0
        self._write_bytes = 0
        self._slice_pair = None
        self._next_slice_flag = None
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._reader,
            args=(handle, self.emit_event, self._stop),
            kwargs={"emit_hex": self._emit_hex},
            name="bcs-reader",
            daemon=True,
        )
        self._thread.start()
        # Only the masked address leaves the process, so the log shows which watch, not where. The
        # two link-option names travel with it: they are what the caller asked for, never a value
        # from the watch.
        return {
            "id": ident,
            "ok": True,
            "address": bcs_bt.mask_address(address),
            "channel": channel,
            "bt_security": security,
            "require_bond": require_bond,
        }

    def _resolve_command(self, ident, command: dict) -> dict:
        """Ask SDP which RFCOMM channel serves the Huawei service. Only that channel may be opened.

        The address comes from the config file, as everywhere else, so the SDP query is about the
        user's own watch. A refusal is a coded response and a sentence; nothing is connected.

        The answer names the watch it asked about, masked, the same way `connect` does: a lookup run
        has to be able to say *which* watch it read SDP for without the process ever printing the
        full address.
        """
        uuid = str(command.get("uuid") or bcs_bt.HUAWEI_SDP_UUID).strip().lower()
        if uuid.replace("-", "") != bcs_bt.HUAWEI_SDP_UUID.replace("-", ""):
            raise bcs_bt.BcsLinkError(
                "bad-uuid",
                f"this sidecar resolves only the Huawei service UUID {bcs_bt.HUAWEI_SDP_UUID}; "
                f"it was asked for {bcs_bt.mask_text(uuid)}",
            )
        expected = command.get("expect_channel")
        if expected is not None and (
            not isinstance(expected, int) or not bcs_bt.CHANNEL_MIN <= expected <= bcs_bt.CHANNEL_MAX
        ):
            raise bcs_bt.BcsLinkError(
                "bad-config",
                f"expect_channel must be {bcs_bt.CHANNEL_MIN}-{bcs_bt.CHANNEL_MAX}, or absent",
            )
        address = self._address_loader(self._config_path)
        sdp = self._sdp_lookup(address, timeout=SDP_TIMEOUT)
        ok, code, message = bcs_bt.verify_sdp_channel(sdp, expected)
        if not ok:
            raise bcs_bt.BcsLinkError(code, message)
        self._verified_channel = sdp.channel
        return {
            "id": ident,
            "ok": True,
            # Masked here, like every other address this process emits, so a lookup run can name the
            # watch it asked about without the full value ever leaving the sidecar.
            "address": bcs_bt.mask_address(address),
            "method": sdp.method,
            "channel": sdp.channel,
            "matched_uuid": bool(sdp.matched_uuid),
            "matched_serial": bool(sdp.matched_serial),
            "expect_channel": expected,
            "detail": bcs_bt.mask_text(sdp.detail),
        }

    def _write_command(self, ident, command: dict) -> dict:
        if not self.is_connected:
            return _write_refused(ident, "write requires an open link")
        encoded = command.get("hex")
        if not isinstance(encoded, str) or not encoded or len(encoded) % 2 or len(encoded) > MAX_WRITE_BYTES * 2:
            return _write_refused(ident, "write frame must be non-empty, even-length hex of at most 1024 bytes")
        if any(character not in "0123456789abcdefABCDEF" for character in encoded):
            return _write_refused(ident, "write frame is not hexadecimal")
        frame = bytes.fromhex(encoded)
        pair, slice_state = self._validate_write_frame(frame)
        if pair is None and slice_state is None:
            return _write_refused(ident, "write frame is invalid or not allowlisted")
        if self._write_count >= MAX_WRITES_PER_CONNECTION or self._write_bytes + len(frame) > MAX_TOTAL_WRITE_BYTES:
            self._slice_pair = None
            self._next_slice_flag = None
            return _write_refused(ident, "write budget for this connection is exhausted")

        self._write_count += 1
        self._write_bytes += len(frame)
        try:
            self._handle.sendall(frame)
        except (TimeoutError, socket.timeout):
            self._shutdown("write timed out")
            return {"id": ident, "ok": False, "code": "timeout", "error": "the link timed out while writing", "errno": None}
        except OSError as exc:
            failure = bcs_bt.classify_connect_error(exc)
            self._shutdown("write failed")
            return {
                "id": ident,
                "ok": False,
                "code": failure.code,
                "error": failure.to_wire()["error"],
                "errno": failure.errno_value,
            }
        self._slice_pair, self._next_slice_flag = slice_state
        return {"id": ident, "ok": True, "bytes": len(frame), "writes": self._write_count}

    def _validate_write_frame(self, frame: bytes) -> tuple[tuple[int, int] | None, tuple[tuple[int, int] | None, int | None] | None]:
        if len(frame) < 8 or frame[0] != 0x5A:
            return None, None
        declared_length = (frame[1] << 8) | frame[2]
        if declared_length != len(frame) - 5:
            return None, None
        if _frame_crc16(frame[:-2]) != ((frame[-2] << 8) | frame[-1]):
            return None, None

        slice_type = frame[3]
        if slice_type == 0:
            if self._slice_pair is not None or len(frame) < 8:
                return None, None
            pair = (frame[4], frame[5])
            return (pair, (None, None)) if pair in WRITE_ALLOWLIST else (None, None)
        if slice_type == 1:
            if self._slice_pair is not None or len(frame) < 9:
                return None, None
            pair = (frame[5], frame[6])
            if pair not in WRITE_ALLOWLIST:
                return None, None
            return pair, ((pair, (frame[4] + 1) & 0xFF) if slice_type != 3 else (None, None))
        if slice_type in (2, 3):
            if self._slice_pair is None or frame[4] != self._next_slice_flag:
                return None, None
            if slice_type == 2:
                return self._slice_pair, (self._slice_pair, (frame[4] + 1) & 0xFF)
            return self._slice_pair, (None, None)
        return None, None

    def _shutdown(self, reason: str) -> None:
        """Close the socket and stop the reader. Idempotent, so close-after-drop is safe."""
        if self._handle is None and self._closed:
            return
        self._stop.set()
        handle, self._handle = self._handle, None
        if handle is not None:
            try:
                handle.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                handle.close()
            except OSError:
                pass
        if (
            self._thread is not None
            and self._thread.is_alive()
            and self._thread is not threading.current_thread()
        ):
            self._thread.join(timeout=2.0)
        self._thread = None
        # Nothing was open, so there is nothing to announce: an empty session stays quiet.
        if handle is not None and not self._closed:
            self._closed = True
            self._emitter.send({"event": "closed", "at": bcs_bt.now_iso(), "reason": reason})

    def run(self, input_stream, output_stream) -> int:
        """Read commands until stdin ends, then close. Returns the process exit code."""
        emitter = self._emitter
        for line in input_stream:
            text = line.strip()
            if not text:
                continue
            try:
                command = json.loads(text)
            except json.JSONDecodeError:
                emitter.send(_protocol_error("a command line was not JSON"))
                continue
            if not isinstance(command, dict):
                emitter.send(_protocol_error("a command was not an object"))
                continue
            emitter.send(self.handle_command(command))
        # The parent closing stdin is the normal end of life: let go of the watch and exit.
        self._shutdown("the parent stopped talking to the sidecar")
        return 0


def _protocol_error(detail: str) -> dict:
    return {"id": None, "ok": False, "code": "protocol", "error": detail, "errno": None}


def _write_refused(ident, reason: str) -> dict:
    return {"id": ident, "ok": False, "code": "write-refused", "error": reason, "errno": None}


def _frame_crc16(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _stdout_is_private_channel(stream) -> bool:
    """True only for the AF_UNIX socketpair Node gives a spawned child's stdout.

    A FIFO, terminal, file, or network socket is refused. Received payload bytes are allowed only
    on the private Node/sidecar channel, so they cannot be redirected into a file or another peer.
    """
    try:
        descriptor = os.dup(stream.fileno())
    except (AttributeError, OSError, ValueError):
        return False
    try:
        with socket.socket(fileno=descriptor) as channel:
            return channel.family == socket.AF_UNIX
    except OSError:
        return False


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="rfcomm_sidecar.py",
        description="BCS helper sidecar: read counts and write only allowlisted auth frames.",
    )
    parser.add_argument(
        "--config",
        default=bcs_bt.DEFAULT_CONFIG_PATH,
        help="path to the watch address file (default: the helper's own config directory)",
    )
    parser.add_argument(
        "--emit-hex",
        action="store_true",
        help="send received bytes as hex through the AF_UNIX protocol socket (all other outputs refused)",
    )
    parser.add_argument(
        "--socket-timeout",
        type=float,
        default=DEFAULT_SOCKET_TIMEOUT,
        help="seconds to wait for an idle read before looping (default: %(default)s)",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=DEFAULT_CONNECT_TIMEOUT,
        help="seconds to allow a connect attempt (default: %(default)s)",
    )
    parser.add_argument(
        "--bt-security",
        choices=sorted(bcs_bt.BT_SECURITY_LEVELS),
        default=DEFAULT_BT_SECURITY,
        help=(
            "ask the stack for this BT_SECURITY level before connect() (default: %(default)s, which "
            "asks for nothing at all; medium means authenticated and encrypted)"
        ),
    )
    parser.add_argument(
        "--require-bond",
        action="store_true",
        help=(
            "refuse to connect unless bluetoothctl reports the watch as paired with this computer; a "
            "precondition check only, this never pairs a watch (default: off)"
        ),
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    # The sidecar's own stdin protocol is JSON on stdout, so exceptional human lines go to stderr.
    # Normal startup is deliberately silent: a clean ping produces zero diagnostic warnings.
    def diag(message: str) -> None:
        print(f"bcs-sidecar: {bcs_bt.mask_text(message)}", file=sys.stderr, flush=True)

    if args.emit_hex and not _stdout_is_private_channel(sys.stdout):
        diag("--emit-hex requires an AF_UNIX socket; received bytes are never sent to another channel")
        return 2
    sidecar = Sidecar(
        Emitter(sys.stdout),
        config_path=args.config,
        emit_hex=args.emit_hex,
        socket_timeout=args.socket_timeout,
        connect_timeout=args.connect_timeout,
        bt_security=args.bt_security,
        require_bond=args.require_bond,
    )
    try:
        return sidecar.run(sys.stdin, sys.stdout)
    except KeyboardInterrupt:
        diag("interrupted")
        sidecar._shutdown("interrupted")  # noqa: SLF001 - the only exit path that owns a live link
        return 130


if __name__ == "__main__":
    sys.exit(main())

