# BCS helper — Phase 1 (link only): tests for the Bluetooth facts, masking and error mapping.
# Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
# See ../NOTICE for attribution and privacy rules.
#
# No Bluetooth hardware, no daemon and no network: every socket, clock and subprocess is a fake,
# so these tests are fast and cannot touch a real watch. They also pin the Phase 1 discipline:
# a refused channel must leave nothing but a closed socket behind.

import errno
import json
import os
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from sidecar import bcs_bt

ADDRESS = "AA:BB:CC:DD:EE:FF"


class FakeSocket:
    """Records what was asked of it. Any write is a test failure, not a recorded call."""

    def __init__(self, address="", channel=0, error=None, recv_plan=None, connect_error=None):
        self.address = address
        self.channel = channel
        self.connected = False
        self.closed = False
        self.shutdown_called = False
        self.timeout = None
        self.sent = []
        self.connect_error = connect_error
        self.recv_plan = list(recv_plan or [])
        self.error = error
        # Phase 3G: what the stack was asked before connect(), and in which order.
        self.options = []
        self.calls = []

    def connect(self, target):
        self.address, self.channel = target
        self.calls.append("connect")
        if self.connect_error is not None:
            raise self.connect_error
        self.connected = True

    def settimeout(self, value):
        self.timeout = value
        self.calls.append("settimeout")

    def setsockopt(self, level, option, value):
        self.options.append((level, option, value))
        self.calls.append("setsockopt")

    def send(self, data):  # pragma: no cover - Phase 1 must never reach this
        self.sent.append(data)
        raise AssertionError("Phase 1 wrote bytes to the watch")

    def shutdown(self, how):  # noqa: ARG002 - signature mirrors a real socket
        self.shutdown_called = True

    def close(self):
        self.closed = True

    def recv(self, size):  # noqa: ARG002 - the size is the real socket's business
        if self.recv_plan:
            step = self.recv_plan.pop(0)
            if isinstance(step, BaseException):
                raise step
            return step
        raise socket.timeout()


def connect_factory(plan):
    """A factory whose nth socket answers with plan[n] = None (accept) or an exception."""

    def factory(timeout):
        index = len(factory.made)
        outcome = plan[index] if index < len(plan) else OSError(errno.ECONNREFUSED, "no service")
        error = outcome if isinstance(outcome, BaseException) else None
        handle = FakeSocket(error=error, connect_error=error)
        factory.made.append(handle)
        factory.timeouts.append(timeout)
        return handle

    factory.made = []
    factory.timeouts = []
    return factory


class MaskTest(unittest.TestCase):
    def test_valid_addresses_keep_only_the_last_two_octets(self):
        self.assertEqual("XX:XX:XX:XX:EE:FF", bcs_bt.mask_address(ADDRESS))
        self.assertEqual("XX:XX:XX:XX:EE:FF", bcs_bt.mask_address("aa:bb:cc:dd:ee:ff"))

    def test_anything_unusable_becomes_the_placeholder(self):
        for bad in ("", None, "AA:BB", "AA:BB:CC:DD:EE:FFF", "AA:BB:CC:DD:EE", "zz:bb:cc:dd:ee:ff"):
            self.assertEqual(bcs_bt.MASKED_ADDRESS, bcs_bt.mask_address(bad))

    def test_text_masking_finds_an_address_inside_a_sentence(self):
        text = f"Device {ADDRESS} connected"
        self.assertEqual("Device XX:XX:XX:XX:EE:FF connected", bcs_bt.mask_text(text))

    def test_text_masking_is_idempotent_so_it_can_be_applied_twice(self):
        once = bcs_bt.mask_text(ADDRESS)
        self.assertEqual(once, bcs_bt.mask_text(once))

    def test_text_masking_leaves_hex_that_is_not_an_address_alone(self):
        payload = "1a2b3c4d" * 4
        self.assertEqual(payload, bcs_bt.mask_text(payload))


class AddressFileTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.directory.name, "watch.json")
        self.addCleanup(self.directory.cleanup)

    def test_saving_then_loading_round_trips_and_writes_mode_0600(self):
        bcs_bt.save_watch_address(ADDRESS, self.path)
        self.assertEqual(ADDRESS, bcs_bt.load_watch_address(self.path))
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(0o600, mode)

    def test_saving_creates_the_directory_so_a_fresh_machine_works(self):
        nested = os.path.join(self.directory.name, "aether-bcs", "watch.json")
        bcs_bt.save_watch_address(ADDRESS, nested)
        self.assertTrue(os.path.exists(nested))

    def test_a_missing_file_says_so_with_the_no_config_code(self):
        with self.assertRaises(bcs_bt.BcsLinkError) as caught:
            bcs_bt.load_watch_address(self.path)
        self.assertEqual("no-config", caught.exception.code)

    def test_a_file_that_is_not_json_is_a_bad_config(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("not json at all")
        with self.assertRaises(bcs_bt.BcsLinkError) as caught:
            bcs_bt.load_watch_address(self.path)
        self.assertEqual("bad-config", caught.exception.code)

    def test_a_file_without_an_address_is_a_bad_config(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"address": "nope"}))
        with self.assertRaises(bcs_bt.BcsLinkError) as caught:
            bcs_bt.load_watch_address(self.path)
        self.assertEqual("bad-config", caught.exception.code)

    def test_saving_a_bad_address_is_refused(self):
        with self.assertRaises(bcs_bt.BcsLinkError) as caught:
            bcs_bt.save_watch_address("not-an-address", self.path)
        self.assertEqual("bad-config", caught.exception.code)


class ErrorMappingTest(unittest.TestCase):
    def map(self, exc):
        return bcs_bt.classify_connect_error(exc)

    def test_busy_explains_the_likely_cause(self):
        failure = self.map(OSError(errno.EBUSY, "Device or resource busy"))
        self.assertEqual("busy", failure.code)
        self.assertEqual(errno.EBUSY, failure.errno_value)
        self.assertIn("phone", str(failure))

    def test_refused_is_the_ordinary_answer_for_a_channel_without_a_service(self):
        self.assertEqual("refused", self.map(OSError(errno.ECONNREFUSED, "refused")).code)

    def test_timeout_covers_both_the_errno_and_a_plain_timeout(self):
        self.assertEqual("timeout", self.map(OSError(errno.ETIMEDOUT, "timed out")).code)
        self.assertEqual("timeout", self.map(TimeoutError("timed out")).code)

    def test_permission_and_unreachable_are_kept_apart(self):
        self.assertEqual("permission", self.map(OSError(errno.EACCES, "denied")).code)
        self.assertEqual("unreachable", self.map(OSError(errno.EHOSTUNREACH, "no route")).code)

    def test_a_permission_error_with_a_security_level_is_a_refused_secure_link(self):
        # Phase 3G (D3): with --bt-security set, EACCES/EPERM is the stack refusing the *secure*
        # link, which is almost always a missing bond — not a local daemon problem.
        for number in (errno.EACCES, errno.EPERM):
            with self.subTest(errno=number):
                failure = bcs_bt.classify_connect_error(OSError(number, "denied"), security="medium")
                self.assertEqual("security-refused", failure.code)
                self.assertEqual(number, failure.errno_value)
                self.assertIn("not bonded", str(failure))
                self.assertNotIn("access to the Bluetooth daemon", str(failure))

    def test_the_old_daemon_sentence_stays_for_a_link_without_a_level(self):
        failure = bcs_bt.classify_connect_error(OSError(errno.EACCES, "denied"), security="none")
        self.assertEqual("permission", failure.code)
        self.assertIn("access to the Bluetooth daemon", str(failure))

    def test_the_two_timeouts_say_which_one_timed_out(self):
        ours = bcs_bt.classify_connect_error(TimeoutError("timed out"), timeout=10.0)
        self.assertEqual("timeout", ours.code)
        self.assertIn("no answer within the 10s this helper allows", str(ours))
        stack = bcs_bt.classify_connect_error(OSError(errno.ETIMEDOUT, "timed out"), timeout=10.0)
        self.assertEqual("timeout", stack.code)
        self.assertIn("the Bluetooth stack reported a timeout", str(stack))
        self.assertNotIn("this helper allows", str(stack))

    def test_reset_is_reported_as_reset_not_as_refused(self):
        self.assertEqual("reset", self.map(OSError(errno.ECONNRESET, "reset by peer")).code)

    def test_an_unusual_oserror_is_unknown_and_keeps_its_errno(self):
        failure = self.map(OSError(errno.EIO, "input/output error"))
        self.assertEqual("unknown", failure.code)
        self.assertEqual(errno.EIO, failure.errno_value)

    def test_a_bcs_error_passes_through_untouched(self):
        original = bcs_bt.BcsLinkError("unsupported", "no bluetooth in this python")
        self.assertIs(original, self.map(original))

    def test_the_wire_shape_is_what_the_typescript_side_parses(self):
        wire = bcs_bt.BcsLinkError("busy", f"watch busy at {ADDRESS}", errno.EBUSY).to_wire()
        self.assertEqual({"ok", "code", "error", "errno"}, set(wire))
        self.assertFalse(wire["ok"])
        self.assertEqual("busy", wire["code"])
        self.assertNotIn(ADDRESS, wire["error"])


class ConnectChannelTest(unittest.TestCase):
    def test_connecting_returns_the_open_socket_without_writing(self):
        factory = connect_factory([None])
        handle = bcs_bt.connect_channel(ADDRESS, 15, 2.5, factory)
        self.assertTrue(handle.connected)
        self.assertEqual((ADDRESS, 15), (handle.address, handle.channel))
        self.assertEqual(2.5, factory.timeouts[0])
        self.assertEqual([], handle.sent)

    def test_a_failed_connect_closes_the_socket_and_raises_a_coded_error(self):
        factory = connect_factory([OSError(errno.ECONNREFUSED, "refused")])
        with self.assertRaises(bcs_bt.BcsLinkError) as caught:
            bcs_bt.connect_channel(ADDRESS, 3, 1.0, factory)
        self.assertEqual("refused", caught.exception.code)
        self.assertTrue(factory.made[0].closed)

    def test_a_channel_outside_the_range_is_refused_before_anything_is_opened(self):
        factory = connect_factory([None])
        for channel in (0, 31, -1, "5", None):
            with self.assertRaises(bcs_bt.BcsLinkError) as caught:
                bcs_bt.connect_channel(ADDRESS, channel, 1.0, factory)
            self.assertEqual("bad-config", caught.exception.code)
        self.assertEqual([], factory.made)


class BtSecurityTest(unittest.TestCase):
    """Phase 3G (D1): the opt-in BT_SECURITY level, and the fact that it is off by default."""

    def test_the_four_names_map_to_the_linux_levels(self):
        self.assertIsNone(bcs_bt.bt_security_level("none"))
        self.assertEqual(1, bcs_bt.bt_security_level("low"))
        self.assertEqual(2, bcs_bt.bt_security_level("medium"))
        self.assertEqual(3, bcs_bt.bt_security_level("high"))

    def test_a_name_outside_the_four_is_refused_before_a_socket_exists(self):
        made = []

        def factory(timeout, security="none"):  # pragma: no cover - must not be reached
            made.append(security)
            return FakeSocket()

        for bad in ("MEDIUM", "medium ", "", None, 2, "fips"):
            with self.subTest(bad=bad):
                with self.assertRaises(bcs_bt.BcsLinkError) as caught:
                    bcs_bt.connect_channel(ADDRESS, 5, 1.0, factory, security=bad)
                self.assertEqual("bad-config", caught.exception.code)
                self.assertIn("low", str(caught.exception))
        self.assertEqual([], made, "an unknown level must not reach the socket factory")

    def test_a_level_is_a_two_byte_option_applied_before_connect(self):
        # The real socket factory is used, with socket.socket replaced: this is the only way to see
        # the optval and its length. `struct bt_security` is two bytes, so a bare int (four bytes)
        # would be the wrong length for the option.
        made = []

        def fake_socket(family, kind, proto):  # noqa: ARG001 - mirrors the real signature
            handle = FakeSocket()
            made.append(handle)
            return handle

        with patch("socket.socket", fake_socket):
            handle = bcs_bt.connect_channel(ADDRESS, 5, 2.0, bcs_bt.rfcomm_socket, security="medium")

        self.assertEqual(1, len(made))
        self.assertEqual(
            [
                (bcs_bt.SOL_BLUETOOTH, bcs_bt.BT_POWER_OPTION, bytes([1])),
                (bcs_bt.SOL_BLUETOOTH, bcs_bt.BT_SECURITY_OPTION, bytes([2, 0])),
            ],
            handle.options,
        )
        self.assertEqual(2, len(handle.options[1][2]))
        self.assertEqual(["setsockopt", "setsockopt", "settimeout", "connect"], handle.calls)
        self.assertTrue(handle.connected)

    def test_the_default_asks_the_stack_for_nothing_and_is_unchanged(self):
        handle = FakeSocket()
        bcs_bt.connect_channel(ADDRESS, 5, 2.0, lambda timeout: handle)
        self.assertEqual([], handle.options)
        self.assertEqual(["connect"], handle.calls)

    def test_the_timeout_and_the_level_travel_to_the_factory_together(self):
        seen = []

        def factory(timeout, security="none"):
            seen.append((timeout, security))
            return FakeSocket()

        handle = bcs_bt.connect_channel(ADDRESS, 7, 3.5, factory, security="high")
        self.assertEqual([(3.5, "high")], seen)
        self.assertTrue(handle.connected)


class RfcommPowerTest(unittest.TestCase):
    def test_an_unsupported_power_option_is_ignored_and_the_socket_still_connects(self):
        handle = FakeSocket()
        original = handle.setsockopt

        def setsockopt(level, option, value):
            if option == bcs_bt.BT_POWER_OPTION:
                raise OSError(errno.ENOPROTOOPT, "option unavailable")
            original(level, option, value)

        handle.setsockopt = setsockopt
        with patch("socket.socket", lambda *args: handle):
            result = bcs_bt.rfcomm_socket(2.0)
        self.assertIs(handle, result)
        self.assertEqual(2.0, handle.timeout)
        self.assertFalse(handle.closed)

    def test_any_other_power_option_failure_closes_the_socket(self):
        handle = FakeSocket()

        def setsockopt(level, option, value):  # noqa: ARG001
            raise OSError(errno.EACCES, "denied")

        handle.setsockopt = setsockopt
        with patch("socket.socket", lambda *args: handle):
            with self.assertRaises(OSError):
                bcs_bt.rfcomm_socket(2.0)
        self.assertTrue(handle.closed)


BONDED_YES = """
Device AA:BB:CC:DD:EE:FF (public)
\tName: Watch
\tPaired: yes
\tBonded: yes
\tTrusted: yes
"""

BONDED_NO = """
Device AA:BB:CC:DD:EE:FF (public)
\tPaired: no
\tBonded: no
"""

BONDED_ABSENT = """
Device AA:BB:CC:DD:EE:FF (public)
\tPaired: yes
"""


class BondProbeTest(unittest.TestCase):
    """Phase 3G (D2): the bond precondition — a check, never a pairing feature."""

    def probe(self, stdout="", stderr="", tools=("bluetoothctl",), error=None):
        calls = []

        def which(name):
            return f"/usr/bin/{name}" if name in tools else None

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            if error is not None:
                raise error
            return Completed(stdout, stderr)

        return bcs_bt.probe_bond(ADDRESS, which=which, runner=runner, timeout=4.0), calls

    def test_only_a_positive_answer_passes(self):
        result, calls = self.probe(BONDED_YES)
        self.assertTrue(result.bonded)
        self.assertTrue(bcs_bt.verify_bond(result)[0])
        # It asked bluetoothctl for "info" and nothing else: no pair, no connect, no scan.
        self.assertEqual(["bluetoothctl", "info", ADDRESS], calls[0][0])
        self.assertEqual(4.0, calls[0][1]["timeout"])

    def test_the_line_is_found_whichever_half_of_the_output_carries_it(self):
        self.assertTrue(self.probe("", stderr=BONDED_YES)[0].bonded)
        self.assertTrue(self.probe("  bonded: YES\n")[0].bonded)

    def test_not_paired_is_a_not_bonded_refusal_that_says_what_to_do(self):
        result, _calls = self.probe(BONDED_NO)
        self.assertFalse(result.bonded)
        ok, code, message = bcs_bt.verify_bond(result)
        self.assertFalse(ok)
        self.assertEqual("not-bonded", code)
        self.assertIn("bluetoothctl pair", message)
        self.assertIn("never pairs", message)
        self.assertIn("No link was opened", message)

    def test_an_answer_without_the_line_cannot_be_treated_as_paired(self):
        result, _calls = self.probe(BONDED_ABSENT)
        self.assertIsNone(result.bonded)
        ok, code, message = bcs_bt.verify_bond(result)
        self.assertFalse(ok)
        self.assertEqual("not-bonded", code)
        self.assertIn("could not be verified", message)

    def test_without_bluetoothctl_the_state_is_unverifiable_and_not_a_pass(self):
        result, calls = self.probe(tools=())
        self.assertEqual("unavailable", result.method)
        self.assertIsNone(result.bonded)
        self.assertEqual([], calls)
        self.assertEqual("not-bonded", bcs_bt.verify_bond(result)[1])

    def test_bluetoothctl_not_answering_is_an_answer_not_an_exception(self):
        result, _calls = self.probe(error=subprocess.TimeoutExpired("bluetoothctl", 4.0))
        self.assertIsNone(result.bonded)
        self.assertIn("did not answer", result.detail)
        self.assertEqual("not-bonded", bcs_bt.verify_bond(result)[1])

    def test_no_sentence_ever_carries_an_address(self):
        for answer in (BONDED_YES, BONDED_NO, BONDED_ABSENT):
            result, _calls = self.probe(answer)
            _ok, _code, message = bcs_bt.verify_bond(result)
            self.assertNotIn(ADDRESS, message)


SDPTOOL_DUMP = """
Service Name: Serial Port
Service Description: Serial port service
Service RecHandle: 0x10000
Service Class ID List:
  "Serial Port" (0x1101)
Protocol Descriptor List:
  "L2CAP" (0x0100)
    PSM: 3
  "RFCOMM" (0x0003)
    Channel: 7
Service Name: Hands-Free Voice Gateway
Service RecHandle: 0x10001
Service Class ID List:
  "Handsfree" (0x111f)
Protocol Descriptor List:
  "RFCOMM" (0x0003)
    Channel: 9
"""

# The Huawei record may be named by its UUID instead of by the profile name.
HUAWEI_DUMP = """
Service RecHandle: 0x10002
Service Class ID List:
  UUID 128: 82ff3820-8411-400c-b85a-55bdb32cf060
Protocol Descriptor List:
  "RFCOMM" (0x0003)
    Channel: 21
"""


class SdptoolParseTest(unittest.TestCase):
    def test_the_serial_record_wins_over_another_rfcomm_service(self):
        self.assertEqual(7, bcs_bt.channel_from_sdptool(SDPTOOL_DUMP))

    def test_the_huawei_uuid_identifies_the_record_the_way_the_name_does(self):
        self.assertEqual(21, bcs_bt.channel_from_sdptool(HUAWEI_DUMP))

    def test_a_single_channel_is_used_even_without_a_serial_marker(self):
        dump = 'Service RecHandle: 0x1\n  "RFCOMM" (0x0003)\n    Channel: 4\n'
        self.assertEqual(4, bcs_bt.channel_from_sdptool(dump))

    def test_several_channels_without_a_marker_are_not_guessed(self):
        dump = '  "RFCOMM" (0x0003)\n    Channel: 4\n  "RFCOMM" (0x0003)\n    Channel: 6\n'
        self.assertIsNone(bcs_bt.channel_from_sdptool(dump))

    def test_nothing_to_read_is_not_a_crash(self):
        self.assertIsNone(bcs_bt.channel_from_sdptool(""))
        self.assertIsNone(bcs_bt.channel_from_sdptool("Device AA:BB:CC:DD:EE:FF not available"))


class SerialChannelRecordTest(unittest.TestCase):
    """The parse with its evidence attached: what the channel it returns actually proves."""

    def test_the_huawei_uuid_is_the_strongest_evidence(self):
        self.assertEqual((21, "huawei"), bcs_bt.serial_channel_record(HUAWEI_DUMP))

    def test_uuid128_case_compact_and_bluetooth_byte_orders_match_the_same_record(self):
        forms = (
            "82FF3820-8411-400C-B85A-55BDB32CF060",
            "82ff38208411400cb85a55bdb32cf060",
            "2038ff82-1184-0c40-b85a-55bdb32cf060",
            "60f02cb3-bd55-5ab8-0c40-11842038ff82",
        )
        for value in forms:
            with self.subTest(value=value):
                dump = HUAWEI_DUMP.replace(bcs_bt.HUAWEI_SDP_UUID, value)
                self.assertEqual((21, "huawei"), bcs_bt.serial_channel_record(dump))

    def test_the_serial_profile_name_is_accepted_too(self):
        self.assertEqual((7, "serial"), bcs_bt.serial_channel_record(SDPTOOL_DUMP))

    def test_a_lone_channel_is_a_guess_and_says_so(self):
        dump = 'Service RecHandle: 0x1\n  "RFCOMM" (0x0003)\n    Channel: 4\n'
        self.assertEqual((4, "only"), bcs_bt.serial_channel_record(dump))

    def test_several_channels_without_a_marker_are_no_answer_at_all(self):
        dump = '  "RFCOMM" (0x0003)\n    Channel: 4\n  "RFCOMM" (0x0003)\n    Channel: 6\n'
        self.assertEqual((None, ""), bcs_bt.serial_channel_record(dump))

    def test_an_empty_dump_is_no_answer_rather_than_an_error(self):
        self.assertEqual((None, ""), bcs_bt.serial_channel_record(""))


def sdp(channel=18, matched_uuid=True, matched_serial=False, method="sdptool", detail="sdptool named it"):
    """A result with the evidence a caller can control, so the gate can be tested case by case."""
    return bcs_bt.SdpResult(
        method,
        channel,
        detail,
        matched_uuid=matched_uuid,
        matched_serial=matched_serial,
    )


class VerifySdpChannelTest(unittest.TestCase):
    """The gate: SDP names the channel, or no link is opened. There is no third option."""

    def test_the_uuid_record_and_the_saved_channel_are_accepted(self):
        self.assertEqual((True, "", ""), bcs_bt.verify_sdp_channel(sdp(), 18))

    def test_without_a_saved_channel_there_is_nothing_to_agree_with(self):
        self.assertTrue(bcs_bt.verify_sdp_channel(sdp(channel=9), None)[0])

    def test_the_serial_profile_alone_counts_as_evidence(self):
        self.assertTrue(bcs_bt.verify_sdp_channel(sdp(matched_uuid=False, matched_serial=True), 18)[0])

    def test_sdp_that_cannot_be_read_is_refused_and_names_the_fix(self):
        ok, code, message = bcs_bt.verify_sdp_channel(sdp(channel=None, method="unavailable"), None)
        self.assertFalse(ok)
        self.assertEqual("sdp-unavailable", code)
        self.assertIn("sdptool", message)
        self.assertIn("No link was opened", message)

    def test_sdp_that_names_no_channel_is_refused_without_guessing(self):
        ok, code, message = bcs_bt.verify_sdp_channel(sdp(channel=None, detail="no serial record"), 18)
        self.assertFalse(ok)
        self.assertEqual("sdp-no-channel", code)
        self.assertIn("never used instead", message)

    def test_a_channel_with_no_evidence_behind_it_is_refused(self):
        ok, code, message = bcs_bt.verify_sdp_channel(sdp(matched_uuid=False, matched_serial=False), None)
        self.assertFalse(ok)
        self.assertEqual("sdp-unconfirmed", code)
        self.assertIn(bcs_bt.HUAWEI_SDP_UUID, message)

    def test_a_disagreement_names_both_numbers_and_the_way_forward(self):
        ok, code, message = bcs_bt.verify_sdp_channel(sdp(channel=15), 18)
        self.assertFalse(ok)
        self.assertEqual("sdp-disagreement", code)
        self.assertIn("15", message)
        self.assertIn("18", message)
        self.assertIn("--channel 15", message)

    def test_every_refusal_says_that_no_link_was_opened(self):
        cases = [
            (sdp(channel=None, method="unavailable"), None, "sdp-unavailable"),
            (sdp(channel=None), 18, "sdp-no-channel"),
            (sdp(matched_uuid=False, matched_serial=False), None, "sdp-unconfirmed"),
            (sdp(channel=4), 18, "sdp-disagreement"),
        ]
        for result, expected, code in cases:
            ok, actual, message = bcs_bt.verify_sdp_channel(result, expected)
            self.assertFalse(ok)
            self.assertEqual(code, actual)
            self.assertIn("No link was opened", message, code)


class LookupSdpEvidenceTest(unittest.TestCase):
    """lookup_sdp has to record what the answer proved, not only the number it found."""

    def test_a_huawei_record_is_reported_as_confirmed_evidence(self):
        result = bcs_bt.lookup_sdp(
            ADDRESS,
            which=lambda name: f"/usr/bin/{name}",
            runner=lambda argv, **kwargs: Completed(HUAWEI_DUMP),  # noqa: ARG005
        )
        self.assertEqual(21, result.channel)
        self.assertTrue(result.matched_uuid)
        self.assertFalse(result.matched_serial)
        self.assertTrue(result.confirmed)

    def test_a_lone_channel_from_sdptool_is_reported_as_unconfirmed(self):
        dump = 'Service RecHandle: 0x1\n  "RFCOMM" (0x0003)\n    Channel: 4\n'
        result = bcs_bt.lookup_sdp(
            ADDRESS,
            which=lambda name: f"/usr/bin/{name}",
            runner=lambda argv, **kwargs: Completed(dump),  # noqa: ARG005
        )
        self.assertEqual(4, result.channel)
        self.assertFalse(result.confirmed)


class Completed:
    def __init__(self, stdout="", stderr=""):
        self.stdout = stdout
        self.stderr = stderr


class LookupSdpTest(unittest.TestCase):
    def test_sdptool_is_preferred_and_its_channel_is_used(self):
        seen = []

        def runner(argv, **kwargs):  # noqa: ARG001 - mirrors subprocess.run's keywords
            seen.append(argv)
            return Completed(SDPTOOL_DUMP)

        result = bcs_bt.lookup_sdp(ADDRESS, which=lambda name: f"/usr/bin/{name}", runner=runner)
        self.assertEqual(("sdptool", 7), (result.method, result.channel))
        self.assertEqual(["sdptool", "browse", ADDRESS], seen[0])

    def test_sdptool_running_but_finding_nothing_is_reported_as_such(self):
        result = bcs_bt.lookup_sdp(
            ADDRESS,
            which=lambda name: f"/usr/bin/{name}",
            runner=lambda argv, **kwargs: Completed("no such device"),
        )
        self.assertEqual("sdptool", result.method)
        self.assertIsNone(result.channel)
        self.assertIn("no serial-port record", result.detail)

    def test_a_sdptool_timeout_is_an_answer_not_an_exception(self):
        def runner(argv, **kwargs):  # noqa: ARG001
            raise bcs_bt.subprocess.TimeoutExpired("sdptool", 20)

        result = bcs_bt.lookup_sdp(ADDRESS, which=lambda name: "/usr/bin/sdptool", runner=runner)
        self.assertIsNone(result.channel)
        self.assertIn("did not answer", result.detail)

    def test_without_sdptool_bluetoothctl_can_only_confirm_the_uuid(self):
        def runner(argv, **kwargs):  # noqa: ARG001
            return Completed(f"Device {ADDRESS}\n\tUUID: Serial Port     (00001101-0000-1000-8000-00805f9b34fb)")

        result = bcs_bt.lookup_sdp(
            ADDRESS,
            which=lambda name: None if name == "sdptool" else "/usr/bin/bluetoothctl",
            runner=runner,
        )
        self.assertEqual("bluetoothctl", result.method)
        self.assertIsNone(result.channel)
        self.assertTrue(result.saw_spp_uuid)
        self.assertIn("never the RFCOMM channel", result.detail)

    def test_no_tools_at_all_is_said_plainly(self):
        result = bcs_bt.lookup_sdp(ADDRESS, which=lambda name: None)  # noqa: ARG005
        self.assertEqual("unavailable", result.method)
        self.assertIsNone(result.channel)


class SdpRetryTest(unittest.TestCase):
    def test_a_sleeping_acl_link_gets_three_bounded_attempts_with_short_backoff(self):
        answers = iter((Completed(stderr="Connected: no"), Completed("Connected: no"), Completed(HUAWEI_DUMP)))
        calls = []
        sleeps = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return next(answers)

        result = bcs_bt.lookup_sdp(
            ADDRESS, which=lambda name: "/usr/bin/sdptool", runner=runner, sleep=sleeps.append
        )
        self.assertEqual(21, result.channel)
        self.assertTrue(result.matched_uuid)
        self.assertEqual(3, len(calls))
        self.assertEqual([0.25, 0.5], sleeps)

    def test_a_persistent_sleeping_link_stops_after_three_attempts(self):
        calls = []
        result = bcs_bt.lookup_sdp(
            ADDRESS,
            which=lambda name: "/usr/bin/sdptool",
            runner=lambda argv, **kwargs: calls.append(argv) or Completed(stderr="Connected: no"),
            sleep=lambda seconds: None,
        )
        self.assertIsNone(result.channel)
        self.assertEqual(3, len(calls))
        self.assertIn("stayed asleep", result.detail)

    def test_an_unrelated_empty_answer_is_not_retried(self):
        calls = []
        result = bcs_bt.lookup_sdp(
            ADDRESS,
            which=lambda name: "/usr/bin/sdptool",
            runner=lambda argv, **kwargs: calls.append(argv) or Completed("no serial service"),
            sleep=lambda seconds: self.fail("an unrelated SDP answer must not sleep"),
        )
        self.assertIsNone(result.channel)
        self.assertEqual(1, len(calls))


class Clock:
    """A monotonic clock a test controls: values in order, then the last one forever."""

    def __init__(self, values):
        self._values = list(values)
        self._last = self._values[-1] if self._values else 0.0

    def __call__(self):
        if self._values:
            self._last = self._values.pop(0)
        return self._last


class ProbeChannelsTest(unittest.TestCase):
    def setUp(self):
        self.frozen = Clock([0.0])

    def test_it_stops_at_the_first_channel_that_accepts(self):
        plan = [OSError(errno.ECONNREFUSED, "no service")] * 14 + [None]
        factory = connect_factory(plan)
        outcome = bcs_bt.probe_channels(ADDRESS, timeout=1.0, factory=factory, clock=self.frozen)
        self.assertEqual(15, outcome.accepted)
        self.assertEqual(15, len(outcome.results))
        self.assertEqual("accepted", outcome.results[-1].outcome)
        self.assertTrue(all(handle.closed for handle in factory.made))
        self.assertEqual(15, len(factory.made))

    def test_nothing_is_written_while_probing(self):
        factory = connect_factory([OSError(errno.ECONNREFUSED, "no service")] * 3 + [None])
        bcs_bt.probe_channels(ADDRESS, timeout=1.0, factory=factory, clock=self.frozen)
        for handle in factory.made:
            self.assertEqual([], handle.sent)

    def test_a_link_level_failure_stops_the_run_instead_of_walking_30_channels(self):
        factory = connect_factory([OSError(errno.EACCES, "denied")])
        outcome = bcs_bt.probe_channels(ADDRESS, timeout=1.0, factory=factory, clock=self.frozen)
        self.assertIsNone(outcome.accepted)
        self.assertEqual(1, len(outcome.results))
        self.assertEqual("permission", outcome.results[0].code)
        self.assertIn("permission", outcome.aborted_reason or "")

    def test_a_refused_channel_does_not_stop_the_run(self):
        factory = connect_factory([OSError(errno.ECONNREFUSED, "no service")] * 5 + [None])
        outcome = bcs_bt.probe_channels(ADDRESS, timeout=1.0, factory=factory, clock=self.frozen)
        self.assertEqual(6, outcome.accepted)
        self.assertIsNone(outcome.aborted_reason)

    def test_the_budget_stops_a_run_that_would_otherwise_walk_everything(self):
        factory = connect_factory([OSError(errno.ECONNREFUSED, "no service")] * 30)
        outcome = bcs_bt.probe_channels(
            ADDRESS, timeout=1.0, factory=factory, clock=Clock([0.0, 0.0, 5.0, 100.0]), budget=90.0
        )
        self.assertIsNone(outcome.accepted)
        self.assertEqual(2, len(outcome.results))
        self.assertIn("stopped after", outcome.aborted_reason or "")

    def test_each_attempt_is_reported_as_it_happens(self):
        seen = []
        factory = connect_factory([OSError(errno.ECONNREFUSED, "no service")] * 2 + [None])
        bcs_bt.probe_channels(
            ADDRESS, timeout=1.0, factory=factory, clock=self.frozen, on_result=seen.append
        )
        self.assertEqual([1, 2, 3], [result.channel for result in seen])

    def test_the_tally_groups_only_the_failures(self):
        outcome = bcs_bt.ProbeOutcome(
            results=[
                bcs_bt.ProbeResult(1, "refused", "refused", "no service"),
                bcs_bt.ProbeResult(2, "refused", "timeout", "no answer"),
                bcs_bt.ProbeResult(3, "refused", "refused", "no service"),
                bcs_bt.ProbeResult(4, "accepted", None, "connected"),
            ]
        )
        self.assertEqual("refused=2, timeout=1", outcome.failure_tally())

    def test_explicit_channels_are_probed_in_the_order_given(self):
        factory = connect_factory([OSError(errno.ECONNREFUSED, "no service"), None])
        outcome = bcs_bt.probe_channels(
            ADDRESS, channels=[9, 4], timeout=1.0, factory=factory, clock=self.frozen
        )
        self.assertEqual([9, 4], [result.channel for result in outcome.results])
        self.assertEqual(4, outcome.accepted)


class Stop:
    """A threading.Event stand-in, so a read-loop test never waits on a clock."""

    def __init__(self, on_set=None):
        self.flag = False
        self._on_set = on_set

    def is_set(self):
        return self.flag

    def set(self):
        self.flag = True
        if self._on_set:
            self._on_set()


class ReadLoopTest(unittest.TestCase):
    def collect(self):
        events = []
        return events, events.append

    def test_bytes_are_reported_as_a_count_and_a_time_only(self):
        events, emit = self.collect()
        socket_double = FakeSocket(recv_plan=[b"abcdefgh", b""])
        bcs_bt.read_loop(socket_double, emit, Stop())
        self.assertEqual({"event", "bytes", "at"}, set(events[0]))
        self.assertEqual(8, events[0]["bytes"])
        self.assertTrue(events[0]["at"].endswith("Z"))
        self.assertEqual("closed", events[1]["event"])

    def test_hex_is_absent_unless_it_is_asked_for(self):
        events, emit = self.collect()
        bcs_bt.read_loop(FakeSocket(recv_plan=[b"ab", b""]), emit, Stop())
        self.assertNotIn("hex", events[0])

    def test_hex_appears_when_the_caller_opts_in(self):
        events, emit = self.collect()
        bcs_bt.read_loop(FakeSocket(recv_plan=[b"ab", b""]), emit, Stop(), emit_hex=True)
        self.assertEqual("6162", events[0]["hex"])

    def test_an_idle_socket_keeps_the_loop_going(self):
        events, emit = self.collect()
        plan = [socket.timeout(), b"xy", socket.timeout(), b""]
        bcs_bt.read_loop(FakeSocket(recv_plan=plan), emit, Stop())
        self.assertEqual(["data", "closed"], [event["event"] for event in events])

    def test_a_socket_error_ends_the_loop_with_one_coded_event(self):
        events, emit = self.collect()
        stop = Stop()
        bcs_bt.read_loop(FakeSocket(recv_plan=[OSError(errno.ECONNRESET, "reset by peer")]), emit, stop)
        self.assertEqual(1, len(events))
        self.assertEqual("error", events[0]["event"])
        self.assertEqual("reset", events[0]["code"])
        self.assertEqual(errno.ECONNRESET, events[0]["errno"])

    def test_the_stop_flag_ends_the_loop_without_a_closed_event(self):
        events, emit = self.collect()
        socket_double = FakeSocket(recv_plan=[b"one", b"two"])
        stop = Stop()

        def on_data(event):
            emit(event)
            stop.set()

        bcs_bt.read_loop(socket_double, on_data, stop)
        self.assertEqual(1, len(events))
        self.assertEqual(3, events[0]["bytes"])


class ProbeReportTest(unittest.TestCase):
    def test_an_accepted_channel_is_the_headline(self):
        sdp = bcs_bt.SdpResult("sdptool", 15, "sdptool reported it")
        outcome = bcs_bt.ProbeOutcome(results=[bcs_bt.ProbeResult(15, "accepted")], accepted=15)
        lines = bcs_bt.format_probe_report("XX:XX:XX:XX:EE:FF", sdp, outcome, 3.0, "sdp 15 first")
        text = "\n".join(lines)
        self.assertIn("masked_address: XX:XX:XX:XX:EE:FF", text)
        self.assertIn("sdp: sdptool reported channel 15", text)
        self.assertIn("channel: 15", text)
        self.assertIn("result: accepted", text)
        self.assertNotIn("AA:BB:CC:DD:EE:FF", text)

    def test_a_refusal_says_none_and_why_the_run_stopped(self):
        sdp = bcs_bt.SdpResult("bluetoothctl", None, "no SDP browser", saw_spp_uuid=True)
        outcome = bcs_bt.ProbeOutcome(
            results=[bcs_bt.ProbeResult(1, "refused", "busy", "adapter busy")],
            aborted_reason="the Bluetooth adapter or the watch is busy",
        )
        lines = bcs_bt.format_probe_report("XX:XX:XX:XX:EE:FF", sdp, outcome, 3.0, "1-30")
        text = "\n".join(lines)
        self.assertIn("channel: none", text)
        self.assertIn("result: refused", text)
        self.assertIn("failure_codes: busy=1", text)
        self.assertIn("sdp_evidence: huawei_uuid=no serial_port=yes", text)
        self.assertIn("stopped_early", text)


if __name__ == "__main__":
    unittest.main()
