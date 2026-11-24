# BCS helper — sidecar protocol and allowlisted-write tests. Copyright (C) 2026 HyperionOS Project.
# SPDX-License-Identifier: AGPL-3.0-or-later
# See ../NOTICE for attribution and privacy rules.
#
# No sockets, no threads of our own and no Bluetooth: the address loader, the connect call and
# the reader are all injected. Two tests do start the real process, which is how the file-mode
# import path is proven, and even those only ping: nothing in this file can reach a watch.

import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from sidecar import bcs_bt, rfcomm_sidecar

ADDRESS = "AA:BB:CC:DD:EE:FF"
HERE = os.path.dirname(os.path.abspath(__file__))


class FakeSocket:
    """A socket double that records sent frames and returns scripted input bytes."""

    def __init__(self, recv_plan=None):
        self.timeout = None
        self.closed = False
        self.shutdown_called = False
        self.sent = []
        self.recv_plan = list(recv_plan or [])
        self.send_error = None

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)
        if self.send_error is not None:
            raise self.send_error

    def shutdown(self, how):  # noqa: ARG002 - mirrors the real signature
        self.shutdown_called = True

    def close(self):
        self.closed = True

    def recv(self, size):  # noqa: ARG002
        if not self.recv_plan:
            raise TimeoutError()
        step = self.recv_plan.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step


class FakeStream:
    """Stands in for stdout: keeps every line so a test can parse the protocol back."""

    def __init__(self):
        self.chunks = []

    def write(self, text):
        self.chunks.append(text)
        return len(text)

    def flush(self):
        pass

    def messages(self):
        return [json.loads(chunk) for chunk in self.chunks]

    def text(self):
        return "".join(self.chunks)


class Records:
    """What the sidecar asked the injected pieces to do."""

    def __init__(self):
        self.loader_paths = []
        self.connects = []
        self.sockets = []
        self.sdp_queries = []
        # Phase 3G: the security name each connect asked for, and every bond probe that ran.
        self.securities = []
        self.bonds = []


def build(
    address=ADDRESS,
    connect_error=None,
    reader=None,
    emit_hex=False,
    config_path="/tmp/watch.json",
    recv_plan=None,
    sdp_channel=5,
    sdp_result=None,
    sdp_error=None,
    verify=True,
    bt_security="none",
    require_bond=False,
    bond=None,
):
    """A sidecar wired to fakes. By default the reader thread does nothing and returns.

    `verify` resolves the channel through the injected SDP lookup first, because the sidecar refuses
    to connect to a channel SDP did not name in this session. A test that wants that refusal passes
    `verify=False` (never resolved) or a different `sdp_channel` (resolved something else).

    `bt_security` and `require_bond` are the CLI defaults; `bond` is what the injected bond probe
    answers, and defaults to a bonded watch so an option test never depends on the pairing text.
    """
    stream = FakeStream()
    records = Records()

    def loader(path):
        records.loader_paths.append(path)
        if address is None:
            raise bcs_bt.BcsLinkError("no-config", "no saved watch address; run tools/watch-address.py")
        return address

    def connect(target, channel, timeout, security="none"):
        records.connects.append((target, channel, timeout))
        records.securities.append(security)
        if connect_error is not None:
            raise connect_error
        handle = FakeSocket(recv_plan=recv_plan)
        records.sockets.append(handle)
        return handle

    def bond_probe(target):
        records.bonds.append(target)
        if bond is not None:
            return bond
        return bcs_bt.BondResult("bluetoothctl", True, "bluetoothctl reports the watch is paired")

    def lookup(target, timeout=20.0):
        records.sdp_queries.append((target, timeout))
        if sdp_error is not None:
            raise sdp_error
        if sdp_result is not None:
            return sdp_result
        return bcs_bt.SdpResult(
            "sdptool",
            sdp_channel,
            "sdptool named the record carrying the Huawei service UUID",
            matched_uuid=True,
        )

    sidecar = rfcomm_sidecar.Sidecar(
        rfcomm_sidecar.Emitter(stream),
        config_path=config_path,
        emit_hex=emit_hex,
        socket_timeout=0.25,
        connect_timeout=7.0,
        bt_security=bt_security,
        require_bond=require_bond,
        address_loader=loader,
        connect=connect,
        reader=reader if reader is not None else (lambda *args, **kwargs: None),
        sdp_lookup=lookup,
        bond_probe=bond_probe,
    )
    if verify and address is not None:
        # The session starts the way a live run starts: ask SDP, then connect. A failed pre-verify
        # leaves the sidecar unverified on purpose, which is what the gate tests rely on.
        sidecar.handle_command({"id": "verify", "cmd": "resolve_channel", "expect_channel": sdp_channel})
    return sidecar, stream, records


def wait_for(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def make_frame(service, command, payload=b""):
    body = bytes((service, command)) + payload
    header = bytes((0x5A,)) + (len(body) + 1).to_bytes(2, "big") + b"\x00" + body
    return header + rfcomm_sidecar._frame_crc16(header).to_bytes(2, "big")


def make_slice(slice_type, flag, content):
    header = b"\x5A" + (len(content) + 2).to_bytes(2, "big") + bytes((slice_type, flag)) + content
    return header + rfcomm_sidecar._frame_crc16(header).to_bytes(2, "big")


class EmitterTest(unittest.TestCase):
    def test_a_written_line_is_newline_terminated_and_masked(self):
        stream = FakeStream()
        rfcomm_sidecar.Emitter(stream).send({"event": "closed", "reason": f"lost {ADDRESS}"})
        self.assertTrue(stream.text().endswith("\n"))
        self.assertNotIn(ADDRESS, stream.text())
        self.assertIn("XX:XX:XX:XX:EE:FF", stream.text())

    def test_the_emitter_serialises_concurrent_writers_without_interleaving(self):
        stream = FakeStream()
        emitter = rfcomm_sidecar.Emitter(stream)
        threads = [threading.Thread(target=emitter.send, args=({"n": index},)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(8, len(stream.messages()))


class DispatchTest(unittest.TestCase):
    def test_ping_answers_with_the_version(self):
        sidecar, _, _ = build()
        self.assertEqual(
            {
                "id": 1,
                "ok": True,
                "version": rfcomm_sidecar.VERSION,
                "capabilities": list(rfcomm_sidecar.CAPABILITIES),
            },
            sidecar.handle_command({"id": 1, "cmd": "ping"}),
        )

    def test_connect_reads_the_address_from_the_config_file_not_from_the_command(self):
        sidecar, _, records = build()
        response = sidecar.handle_command({"id": 2, "cmd": "connect", "channel": 5, "address": "11:22:33:44:55:66"})
        self.assertTrue(response["ok"])
        self.assertEqual((ADDRESS, 5), (records.connects[0][0], records.connects[0][1]))
        # The resolve before it reads the same file, so the set of paths is one path.
        self.assertEqual(["/tmp/watch.json"], sorted(set(records.loader_paths)))
        self.assertEqual("XX:XX:XX:XX:EE:FF", response["address"])
        self.assertNotIn(ADDRESS, json.dumps(response))

    def test_connect_sets_a_short_read_timeout_so_idle_reads_loop(self):
        sidecar, _, records = build()
        sidecar.handle_command({"id": 2, "cmd": "connect", "channel": 5})
        self.assertEqual(0.25, records.sockets[0].timeout)

    def test_connect_uses_the_transport_timeout_and_caps_an_absurd_one(self):
        sidecar, _, records = build()
        sidecar.handle_command({"id": 2, "cmd": "connect", "channel": 5})
        self.assertEqual(7.0, records.connects[0][2])
        sidecar.handle_command({"id": 3, "cmd": "close"})
        sidecar2, _, records2 = build()
        sidecar2.handle_command({"id": 1, "cmd": "connect", "channel": 5, "timeout_ms": 10_000_000})
        self.assertEqual(rfcomm_sidecar.MAX_CONNECT_TIMEOUT, records2.connects[0][2])

    def test_a_channel_outside_the_range_never_reaches_the_radio(self):
        for channel in (0, 31, None, "5", 4.5):
            sidecar, _, records = build()
            response = sidecar.handle_command({"id": 3, "cmd": "connect", "channel": channel})
            self.assertEqual("bad-config", response["code"])
            self.assertEqual([], records.connects)

    def test_no_saved_address_is_reported_as_no_config(self):
        sidecar, _, records = build(address=None)
        response = sidecar.handle_command({"id": 4, "cmd": "connect", "channel": 5})
        # Nothing resolved the channel either, so the channel gate answers first: still no connect.
        self.assertIn(response["code"], ("channel-unverified", "no-config"))
        self.assertEqual([], records.connects)

    def test_a_failed_connect_becomes_a_masked_coded_response(self):
        failure = bcs_bt.BcsLinkError("busy", f"the watch at {ADDRESS} is busy", 16)
        sidecar, _, _ = build(connect_error=failure)
        response = sidecar.handle_command({"id": 5, "cmd": "connect", "channel": 5})
        self.assertFalse(response["ok"])
        self.assertEqual("busy", response["code"])
        self.assertEqual(16, response["errno"])
        self.assertNotIn(ADDRESS, response["error"])
        self.assertFalse(sidecar.is_connected)

    def test_a_connect_before_any_resolve_is_refused_and_never_reaches_the_radio(self):
        sidecar, _, records = build(verify=False)
        response = sidecar.handle_command({"id": 3, "cmd": "connect", "channel": 5})
        self.assertEqual("channel-unverified", response["code"])
        self.assertIn("resolve_channel", response["error"])
        self.assertIn("never connected to", response["error"])
        self.assertEqual([], records.connects)
        self.assertFalse(sidecar.is_connected)

    def test_a_connect_to_a_different_channel_than_sdp_named_is_refused(self):
        sidecar, _, records = build(sdp_channel=18)
        response = sidecar.handle_command({"id": 3, "cmd": "connect", "channel": 18})
        self.assertTrue(response["ok"])
        sidecar.handle_command({"id": 4, "cmd": "close"})
        other, _, other_records = build(sdp_channel=18)
        refused = other.handle_command({"id": 3, "cmd": "connect", "channel": 5})
        self.assertEqual("channel-unverified", refused["code"])
        self.assertIn("18", refused["error"])
        self.assertEqual([], other_records.connects)
        self.assertEqual([(ADDRESS, 18, 7.0)], records.connects)

    def test_resolve_channel_names_the_channel_and_the_evidence(self):
        sidecar, _, records = build(sdp_channel=18, verify=False)
        response = sidecar.handle_command(
            {"id": 2, "cmd": "resolve_channel", "uuid": bcs_bt.HUAWEI_SDP_UUID, "expect_channel": 18}
        )
        self.assertTrue(response["ok"])
        self.assertEqual(("sdptool", 18), (response["method"], response["channel"]))
        self.assertTrue(response["matched_uuid"])
        self.assertFalse(response["matched_serial"])
        self.assertEqual(18, response["expect_channel"])
        # The SDP query is about the configured watch, and nothing was connected.
        self.assertEqual([(ADDRESS, rfcomm_sidecar.SDP_TIMEOUT)], records.sdp_queries)
        self.assertEqual([], records.connects)
        self.assertNotIn(ADDRESS, json.dumps(response))

    def test_resolve_channel_names_the_watch_it_asked_about_masked(self):
        sidecar, _, _ = build(sdp_channel=18, verify=False)
        response = sidecar.handle_command({"id": 2, "cmd": "resolve_channel"})
        self.assertTrue(response["ok"])
        # A lookup has to be able to say which watch it read SDP for, and only the last two octets
        # may leave the process: the same rule `connect` already follows.
        self.assertEqual("XX:XX:XX:XX:EE:FF", response["address"])
        self.assertNotIn(ADDRESS, json.dumps(response))

    def test_resolve_channel_refuses_a_uuid_that_is_not_the_huawei_one(self):
        sidecar, _, records = build(verify=False)
        response = sidecar.handle_command({"id": 2, "cmd": "resolve_channel", "uuid": "00001101-0000-1000-8000-00805f9b34fb"})
        self.assertEqual("bad-uuid", response["code"])
        self.assertIn(bcs_bt.HUAWEI_SDP_UUID, response["error"])
        self.assertEqual([], records.sdp_queries)
        self.assertEqual([], records.connects)

    def test_resolve_channel_refuses_an_expect_channel_outside_rfcomm(self):
        for expect in (0, 31, "18", 4.5):
            sidecar, _, records = build(verify=False)
            response = sidecar.handle_command({"id": 2, "cmd": "resolve_channel", "expect_channel": expect})
            self.assertEqual("bad-config", response["code"])
            self.assertEqual([], records.sdp_queries)
            self.assertEqual([], records.connects)

    def test_resolve_channel_reports_each_sdp_refusal_with_its_own_code(self):
        cases = [
            (bcs_bt.SdpResult("unavailable", None, "neither tool"), None, "sdp-unavailable"),
            (bcs_bt.SdpResult("sdptool", None, "no serial record"), 18, "sdp-no-channel"),
            (bcs_bt.SdpResult("sdptool", 18, "single record", matched_uuid=False), None, "sdp-unconfirmed"),
            (bcs_bt.SdpResult("sdptool", 15, "named", matched_uuid=True), 18, "sdp-disagreement"),
        ]
        for result, expect, code in cases:
            sidecar, _, records = build(sdp_result=result, verify=False)
            command = {"id": 2, "cmd": "resolve_channel"}
            if expect is not None:
                command["expect_channel"] = expect
            response = sidecar.handle_command(command)
            self.assertFalse(response["ok"], code)
            self.assertEqual(code, response["code"])
            self.assertIn("No link was opened", response["error"])
            self.assertEqual([], records.connects)
            # A refused resolve leaves nothing verified, so a following connect cannot sneak through.
            refused = sidecar.handle_command({"id": 3, "cmd": "connect", "channel": result.channel or 5})
            self.assertEqual("channel-unverified", refused["code"])
            self.assertEqual([], records.connects)

    def test_resolve_channel_with_no_saved_address_is_no_config_and_queries_nothing(self):
        sidecar, _, records = build(address=None, verify=False)
        response = sidecar.handle_command({"id": 2, "cmd": "resolve_channel", "expect_channel": 18})
        self.assertEqual("no-config", response["code"])
        self.assertEqual([], records.sdp_queries)
        self.assertEqual([], records.connects)

    def test_a_second_connect_is_refused_as_already_open(self):
        sidecar, _, records = build()
        sidecar.handle_command({"id": 1, "cmd": "connect", "channel": 5})
        response = sidecar.handle_command({"id": 2, "cmd": "connect", "channel": 5})
        self.assertEqual("already-open", response["code"])
        self.assertEqual(1, len(records.connects))

    def test_open_aux_is_refused_because_phase_4_owns_it(self):
        sidecar, _, _ = build()
        response = sidecar.handle_command({"id": 6, "cmd": "open_aux", "channel": 16})
        self.assertEqual("unsupported", response["code"])
        self.assertIn("Phase 4", response["error"])

    def test_an_unknown_command_is_a_protocol_error_not_a_crash(self):
        sidecar, _, _ = build()
        response = sidecar.handle_command({"id": 7, "cmd": "write_please"})
        self.assertEqual("protocol", response["code"])

    def test_close_shuts_the_socket_down_once_and_says_so(self):
        sidecar, stream, records = build()
        sidecar.handle_command({"id": 1, "cmd": "connect", "channel": 5})
        response = sidecar.handle_command({"id": 2, "cmd": "close"})
        self.assertTrue(response["ok"])
        self.assertTrue(records.sockets[0].shutdown_called)
        self.assertTrue(records.sockets[0].closed)
        self.assertFalse(sidecar.is_connected)
        sidecar.handle_command({"id": 3, "cmd": "close"})
        closed_events = [message for message in stream.messages() if message.get("event") == "closed"]
        self.assertEqual(1, len(closed_events))
        self.assertEqual("closed by the caller", closed_events[0]["reason"])

    def test_nothing_is_ever_sent_to_the_watch(self):
        sidecar, _, records = build()
        sidecar.handle_command({"id": 1, "cmd": "connect", "channel": 5})
        sidecar.handle_command({"id": 2, "cmd": "close"})
        for handle in records.sockets:
            self.assertEqual([], handle.sent)


class LinkOptionsTest(unittest.TestCase):
    """Phase 3G: the two opt-in link options (D1/D2) and the sentence change they arm (D3)."""

    def connect(self, sidecar, **fields):
        return sidecar.handle_command({"id": "c", "cmd": "connect", "channel": 5, **fields})

    def test_the_default_connect_asks_for_no_level_and_runs_no_bond_probe(self):
        sidecar, _stream, records = build()
        response = self.connect(sidecar)
        self.assertTrue(response["ok"])
        self.assertEqual("none", response["bt_security"])
        self.assertFalse(response["require_bond"])
        self.assertEqual(["none"], records.securities)
        self.assertEqual([], records.bonds)

    def test_the_cli_default_reaches_the_socket_and_the_answer_names_it(self):
        sidecar, _stream, records = build(bt_security="medium")
        response = self.connect(sidecar)
        self.assertEqual("medium", response["bt_security"])
        self.assertEqual(["medium"], records.securities)

    def test_a_command_field_overrides_the_cli_default(self):
        sidecar, _stream, records = build(bt_security="low")
        response = self.connect(sidecar, bt_security="high")
        self.assertEqual("high", response["bt_security"])
        self.assertEqual(["high"], records.securities)

    def test_an_unknown_level_is_refused_without_creating_a_socket(self):
        sidecar, _stream, records = build()
        response = self.connect(sidecar, bt_security="fips")
        self.assertFalse(response["ok"])
        self.assertEqual("bad-config", response["code"])
        self.assertEqual([], records.securities)
        self.assertEqual([], records.sockets)
        self.assertFalse(sidecar.is_connected)

    def test_a_bonded_watch_passes_the_precondition_and_connects(self):
        sidecar, _stream, records = build(require_bond=True)
        response = self.connect(sidecar)
        self.assertTrue(response["ok"])
        self.assertTrue(response["require_bond"])
        self.assertEqual([ADDRESS], records.bonds)
        self.assertEqual(1, len(records.sockets))

    def test_require_bond_refuses_before_connect_is_called(self):
        unpaired = bcs_bt.BondResult("bluetoothctl", False, "not paired with this computer")
        sidecar, _stream, records = build(require_bond=True, bond=unpaired)
        response = self.connect(sidecar)
        self.assertFalse(response["ok"])
        self.assertEqual("not-bonded", response["code"])
        # The point of the option: refuse before the socket exists, so nothing at all is opened.
        self.assertEqual([], records.connects)
        self.assertEqual([], records.sockets)
        self.assertFalse(sidecar.is_connected)

    def test_an_unverifiable_bond_refuses_too(self):
        unknown = bcs_bt.BondResult("bluetoothctl", None, "the answer carried no Bonded: line")
        sidecar, _stream, records = build(require_bond=True, bond=unknown)
        response = self.connect(sidecar)
        self.assertEqual("not-bonded", response["code"])
        self.assertEqual([], records.connects)

    def test_the_bond_field_can_arm_the_gate_for_one_connect(self):
        unpaired = bcs_bt.BondResult("bluetoothctl", False, "not paired with this computer")
        sidecar, _stream, records = build(bond=unpaired)
        refused = self.connect(sidecar, require_bond=True)
        self.assertEqual("not-bonded", refused["code"])
        self.assertEqual([ADDRESS], records.bonds)
        self.assertEqual([], records.connects)

    def test_a_non_boolean_bond_field_is_refused(self):
        sidecar, _stream, records = build()
        response = self.connect(sidecar, require_bond="yes")
        self.assertEqual("bad-config", response["code"])
        self.assertEqual([], records.connects)

    def test_the_flags_default_off_and_are_validated_by_the_parser(self):
        self.assertEqual("none", rfcomm_sidecar.parse_args([]).bt_security)
        self.assertFalse(rfcomm_sidecar.parse_args([]).require_bond)
        chosen = rfcomm_sidecar.parse_args(["--bt-security", "high", "--require-bond"])
        self.assertEqual("high", chosen.bt_security)
        self.assertTrue(chosen.require_bond)
        with self.assertRaises(SystemExit):
            rfcomm_sidecar.parse_args(["--bt-security", "fips"])

    def test_the_sidecar_help_names_both_options_and_what_they_do_not_do(self):
        out = io.StringIO()
        with self.assertRaises(SystemExit), redirect_stdout(out):
            rfcomm_sidecar.parse_args(["--help"])
        text = out.getvalue()
        self.assertIn("--bt-security", text)
        self.assertIn("--require-bond", text)
        self.assertIn("BT_SECURITY level before", text)
        self.assertIn("precondition", text)
        self.assertIn("never pairs a watch", text)


class WatchBytesTest(unittest.TestCase):
    def test_arriving_bytes_are_a_count_and_the_channel_and_nothing_more(self):
        sidecar, stream, _ = build(recv_plan=[b"hello", b""], reader=bcs_bt.read_loop, sdp_channel=7)
        sidecar.handle_command({"id": 1, "cmd": "connect", "channel": 7})
        self.assertTrue(wait_for(lambda: any(m.get("event") == "closed" for m in stream.messages())))
        data = [message for message in stream.messages() if message.get("event") == "data"]
        self.assertEqual(1, len(data))
        self.assertEqual(5, data[0]["bytes"])
        self.assertEqual(7, data[0]["channel"])
        self.assertNotIn("hex", data[0])
        self.assertNotIn("hello", stream.text())

    def test_hex_only_appears_when_the_helper_was_started_with_emit_hex(self):
        sidecar, stream, _ = build(recv_plan=[b"hi", b""], reader=bcs_bt.read_loop, emit_hex=True, sdp_channel=7)
        sidecar.handle_command({"id": 1, "cmd": "connect", "channel": 7})
        self.assertTrue(wait_for(lambda: any(m.get("event") == "data" for m in stream.messages())))
        data = [message for message in stream.messages() if message.get("event") == "data"]
        self.assertEqual("6869", data[0]["hex"])

    def test_a_dropped_link_becomes_an_error_event_with_a_code(self):
        sidecar, stream, _ = build(
            recv_plan=[OSError(104, "reset by peer")], reader=bcs_bt.read_loop, sdp_channel=7  # 104 = ECONNRESET
        )
        sidecar.handle_command({"id": 1, "cmd": "connect", "channel": 7})
        self.assertTrue(wait_for(lambda: any(m.get("event") == "error" for m in stream.messages())))
        error = [message for message in stream.messages() if message.get("event") == "error"][0]
        self.assertEqual("reset", error["code"])
        self.assertEqual(7, error["channel"])

    def test_opt_in_payload_is_sent_only_on_the_protocol_pipe(self):
        payload = b"synthetic-received-payload"
        sidecar, stream, _ = build(
            recv_plan=[payload, b""], reader=bcs_bt.read_loop, emit_hex=True, sdp_channel=7
        )
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            sidecar.handle_command({"id": 1, "cmd": "connect", "channel": 7})
            self.assertTrue(wait_for(lambda: any(m.get("event") == "closed" for m in stream.messages())))
        data = [message for message in stream.messages() if message.get("event") == "data"]
        self.assertEqual(payload.hex(), data[0]["hex"])
        self.assertNotIn(payload.decode(), stderr.getvalue())
        self.assertNotIn(payload.hex(), stderr.getvalue())


class RunTest(unittest.TestCase):
    def test_every_line_gets_an_answer_and_broken_lines_do_not_stop_the_session(self):
        sidecar, stream, records = build(sdp_channel=9)
        lines = (
            '{"id":1,"cmd":"ping"}\n'
            "\n"
            '{"id":2,"cmd":"connect","channel":9}\n'
            "not json at all\n"
            '["not","an","object"]\n'
            '{"id":3,"cmd":"close"}\n'
        )
        self.assertEqual(0, sidecar.run(io.StringIO(lines), stream))
        messages = stream.messages()
        # The close command's "closed" event is written before its own acknowledgement.
        self.assertEqual([1, 2, None, None, None, 3], [message.get("id") for message in messages])
        self.assertTrue(messages[0]["ok"])
        self.assertEqual("protocol", messages[2]["code"])
        self.assertEqual("protocol", messages[3]["code"])
        self.assertEqual("closed", messages[4]["event"])
        self.assertTrue(messages[5]["ok"])
        self.assertTrue(records.sockets[0].closed)

    def test_stdin_ending_shuts_the_link_down_and_exits_cleanly(self):
        sidecar, stream, records = build(sdp_channel=9)
        self.assertEqual(0, sidecar.run(io.StringIO('{"id":1,"cmd":"connect","channel":9}\n'), stream))
        closed = [message for message in stream.messages() if message.get("event") == "closed"]
        self.assertEqual(1, len(closed))
        self.assertIn("parent", closed[0]["reason"])
        self.assertTrue(records.sockets[0].closed)
        self.assertFalse(sidecar.is_connected)

    def test_ending_stdin_without_a_link_still_exits_cleanly(self):
        sidecar, stream, _ = build()
        self.assertEqual(0, sidecar.run(io.StringIO(""), stream))
        self.assertEqual([], [message for message in stream.messages() if message.get("event") == "closed"])


class RealProcessTest(unittest.TestCase):
    """The tests that start Python for real, and they are aimed away from any watch."""

    def test_the_process_answers_a_ping_and_refuses_to_connect_without_a_resolve(self):
        script = os.path.join(HERE, "rfcomm_sidecar.py")
        completed = subprocess.run(
            [sys.executable, script, "--config", "/nonexistent/aether-bcs/watch.json"],
            input=(
                '{"id":1,"cmd":"ping"}\n'
                '{"id":2,"cmd":"connect","channel":5}\n'
                '{"id":3,"cmd":"resolve_channel","expect_channel":5}\n'
            ),
            capture_output=True,
            text=True,
            timeout=60,
            cwd=os.path.dirname(HERE),
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("", completed.stderr, "normal startup must emit no diagnostics")
        lines = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        self.assertTrue(lines[0]["ok"])
        self.assertEqual(list(rfcomm_sidecar.CAPABILITIES), lines[0]["capabilities"])
        self.assertEqual(rfcomm_sidecar.VERSION, lines[0]["version"])
        # Nothing resolved the channel, so the connect is refused before the config is even read.
        self.assertEqual("channel-unverified", lines[1]["code"])
        self.assertIn("resolve_channel", lines[1]["error"])
        # The resolve then reaches the config loader, finds no saved watch, and stops there.
        self.assertEqual("no-config", lines[2]["code"])
        self.assertTrue(lines[2]["error"])
        self.assertEqual("", completed.stderr)

    def test_help_works_so_the_process_can_explain_itself(self):
        script = os.path.join(HERE, "rfcomm_sidecar.py")
        completed = subprocess.run(
            [sys.executable, script, "--help"], capture_output=True, text=True, timeout=60, check=False
        )
        self.assertEqual(0, completed.returncode)
        self.assertIn("--emit-hex", completed.stdout)

    def test_emit_hex_is_refused_when_stdout_is_a_terminal(self):
        class TerminalStream(io.StringIO):
            def isatty(self):
                return True

        stderr = io.StringIO()
        with patch.object(rfcomm_sidecar.sys, "stdout", TerminalStream()), patch.object(
            rfcomm_sidecar.sys, "stderr", stderr
        ):
            result = rfcomm_sidecar.main(["--config", "/nonexistent/aether-bcs/watch.json", "--emit-hex"])
        self.assertEqual(2, result)
        self.assertIn("requires an AF_UNIX socket", stderr.getvalue())

    def test_emit_hex_is_refused_when_stdout_is_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "captured.out")
            with open(target, "w", encoding="utf-8") as captured:
                process = subprocess.run(
                    [
                        sys.executable,
                        os.path.join(HERE, "rfcomm_sidecar.py"),
                        "--config",
                        "/nonexistent/aether-bcs/watch.json",
                        "--emit-hex",
                    ],
                    cwd=os.path.dirname(HERE),
                    stdin=subprocess.DEVNULL,
                    stdout=captured,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=60,
                    check=False,
                )
            self.assertEqual(2, process.returncode)
            self.assertIn("requires an AF_UNIX socket", process.stderr)
            with open(target, encoding="utf-8") as captured:
                self.assertEqual("", captured.read(), "a refused run must not write bytes anywhere")

    def test_emit_hex_is_refused_when_stdout_is_a_fifo(self):
        process = subprocess.run(
            [sys.executable, os.path.join(HERE, "rfcomm_sidecar.py"), "--emit-hex"],
            cwd=os.path.dirname(HERE),
            input='{"id":1,"cmd":"ping"}\n',
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(2, process.returncode)
        self.assertIn("requires an AF_UNIX socket", process.stderr)
        self.assertEqual("", process.stdout)

    def test_emit_hex_is_accepted_when_stdout_is_the_socketpair_nodes_spawn_uses(self):
        """The shape that broke the live run.

        Node's `spawn(..., {stdio: "pipe"})` does not hand the child a FIFO: libuv gives it one end
        of an AF_UNIX socketpair, so fd 1 is S_IFSOCK. A FIFO-only check refused `--emit-hex`, the
        sidecar exited 2 with a second diagnostic line, and the driver's live ping failed with
        "cannot start" — while `--self-test` (a shell pipe, so a FIFO) passed and proved nothing.
        """
        try:
            parent_side, child_side = socket.socketpair()
        except (AttributeError, OSError) as unavailable:  # pragma: no cover - platform dependent
            self.skipTest(f"this platform has no socketpair: {unavailable}")
        process = None
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    os.path.join(HERE, "rfcomm_sidecar.py"),
                    "--config",
                    "/nonexistent/aether-bcs/watch.json",
                    "--emit-hex",
                ],
                cwd=os.path.dirname(HERE),
                stdin=subprocess.PIPE,
                stdout=child_side.fileno(),  # the child inherits the socket, exactly as under Node
                stderr=subprocess.PIPE,
                text=True,
            )
            child_side.close()  # the child holds its end; the parent keeps the other
            process.stdin.write('{"id":1,"cmd":"ping"}\n')
            process.stdin.flush()
            reply = self._read_line(parent_side, timeout=30)
            self.assertIsNotNone(reply, "the sidecar did not answer the ping on a socket stdout")
            message = json.loads(reply)
            self.assertTrue(message["ok"], message)
            self.assertEqual(list(rfcomm_sidecar.CAPABILITIES), message["capabilities"])
            self.assertEqual(rfcomm_sidecar.VERSION, message["version"])
            process.stdin.close()
            self.assertEqual(0, process.wait(timeout=30))
            stderr = process.stderr.read()
            self.assertEqual("", stderr, "normal AF_UNIX startup must emit no diagnostics")
        finally:
            if process is not None:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=30)
                if process.stderr is not None and not process.stderr.closed:
                    process.stderr.close()
            parent_side.close()

    @staticmethod
    def _read_line(connection, timeout):
        """One newline-terminated line from a socket, or None if it never arrives."""
        connection.settimeout(timeout)
        buffer = b""
        while b"\n" not in buffer:
            try:
                chunk = connection.recv(4096)
            except (TimeoutError, socket.timeout):
                return None
            if not chunk:
                return None
            buffer += chunk
        return buffer.split(b"\n", 1)[0].decode("utf-8")


class WriteCommandTest(unittest.TestCase):
    def connected(self):
        sidecar, stream, records = build()
        self.assertTrue(sidecar.handle_command({"id": 1, "cmd": "connect", "channel": 5})["ok"])
        return sidecar, stream, records

    def test_write_requires_a_connection_and_does_not_echo_invalid_hex(self):
        sidecar, _, _ = build()
        payload = "5a0103000100"
        response = sidecar.handle_command({"id": 2, "cmd": "write", "hex": payload})
        self.assertEqual("write-refused", response["code"])
        self.assertNotIn(payload, json.dumps(response))

    def test_invalid_frame_forms_are_refused_before_sendall(self):
        good = make_frame(0x01, 0x16)
        invalid = [
            "0",
            "zz",
            "0000000000000000",
            "5a0003000100",  # declared length mismatch
            make_frame(0x7F, 0x7F).hex(),
            (good[:-1] + bytes((good[-1] ^ 1,))).hex(),
            make_frame(0x01, 0x16, bytes(1017)).hex(),  # exceeds 1024 bytes
        ]
        sidecar, _, records = self.connected()
        for encoded in invalid:
            response = sidecar.handle_command({"id": 3, "cmd": "write", "hex": encoded})
            self.assertEqual("write-refused", response["code"], encoded[:12])
            self.assertNotIn("hex", response)
            if len(encoded) >= 4:
                self.assertNotIn(encoded, json.dumps(response))
        self.assertEqual([], records.sockets[0].sent)

    def test_all_auth_allowlist_pairs_use_sendall(self):
        for service, command in rfcomm_sidecar.WRITE_ALLOWLIST:
            with self.subTest(service=service, command=command):
                sidecar, _, records = self.connected()
                frame = make_frame(service, command)
                response = sidecar.handle_command({"id": 2, "cmd": "write", "hex": frame.hex()})
                self.assertTrue(response["ok"])
                self.assertEqual(len(frame), response["bytes"])
                self.assertEqual([frame], records.sockets[0].sent)
                sidecar.handle_command({"id": 3, "cmd": "close"})

    def test_sliced_writes_require_an_allowlisted_first_slice_and_ordered_continuations(self):
        sidecar, _, records = self.connected()
        frames = [
            make_slice(1, 0, b"\x01\x28first"),
            make_slice(2, 1, b"middle"),
            make_slice(3, 2, b"last"),
        ]
        for frame in frames:
            response = sidecar.handle_command({"id": 2, "cmd": "write", "hex": frame.hex()})
            self.assertTrue(response["ok"], response)
        self.assertEqual(frames, records.sockets[0].sent)

        sidecar, _, records = self.connected()
        refused = make_slice(1, 0, b"\x7f\x7fbad")
        response = sidecar.handle_command({"id": 2, "cmd": "write", "hex": refused.hex()})
        self.assertEqual("write-refused", response["code"])
        self.assertEqual([], records.sockets[0].sent)

    def test_write_count_and_total_byte_budgets_are_per_connection(self):
        sidecar, _, records = self.connected()
        short = make_frame(0x01, 0x16)
        for index in range(rfcomm_sidecar.MAX_WRITES_PER_CONNECTION):
            response = sidecar.handle_command({"id": index + 2, "cmd": "write", "hex": short.hex()})
            self.assertTrue(response["ok"])
        refused = sidecar.handle_command({"id": 100, "cmd": "write", "hex": short.hex()})
        self.assertEqual("write-refused", refused["code"])
        self.assertEqual(rfcomm_sidecar.MAX_WRITES_PER_CONNECTION, len(records.sockets[0].sent))

        sidecar, _, records = self.connected()
        large = make_frame(0x01, 0x16, bytes(rfcomm_sidecar.MAX_WRITE_BYTES - 8))
        self.assertEqual(rfcomm_sidecar.MAX_WRITE_BYTES, len(large))
        for index in range(rfcomm_sidecar.MAX_TOTAL_WRITE_BYTES // len(large)):
            self.assertTrue(sidecar.handle_command({"id": index + 2, "cmd": "write", "hex": large.hex()})["ok"])
        refused = sidecar.handle_command({"id": 99, "cmd": "write", "hex": large.hex()})
        self.assertEqual("write-refused", refused["code"])
        self.assertEqual(rfcomm_sidecar.MAX_TOTAL_WRITE_BYTES, sum(map(len, records.sockets[0].sent)))

    def test_closed_and_timed_out_write_sockets_return_coded_errors(self):
        for failure, code in ((OSError(104, "reset"), "reset"), (TimeoutError(), "timeout")):
            sidecar, _, records = self.connected()
            records.sockets[0].send_error = failure
            response = sidecar.handle_command({"id": 2, "cmd": "write", "hex": make_frame(1, 1).hex()})
            self.assertEqual(code, response["code"])
            self.assertFalse(sidecar.is_connected)

if __name__ == "__main__":
    unittest.main()
