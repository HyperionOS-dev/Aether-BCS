# BCS helper — Phase 1 (link only): tests for the two command-line tools, probe-channel and
# watch-address.py. Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
# See NOTICE in this directory for attribution and privacy rules.
#
# Neither tool can reach a watch from here: the address file is a temporary directory, the device
# list comes from a fake runner, and the probe commands used below either fail on the config or
# are told not to connect at all. Both tools are loaded from their paths, because probe-channel
# has no .py suffix and so can never be an importable module.

import contextlib
import importlib.util
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import re
import select
import tempfile
import time
import pty
import unittest
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.dirname(HERE)
ADDRESS = "AA:BB:CC:DD:EE:FF"


def load(name, path):
    """Load a script as a module by path, the way a shell would run it.

    SourceFileLoader is used explicitly because probe-channel has no file extension, so
    spec_from_file_location cannot pick a loader for it.
    """
    loader = SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


watch_tool = load("bcs_watch_address_tool", os.path.join(HELPER, "tools", "watch-address.py"))
probe = load("bcs_probe_channel", os.path.join(HELPER, "probe-channel"))
bcs_bt = probe.bcs_bt


def write_sidecar_stub(bin_dir, started_marker, stopped_marker):
    """A stand-in for python3 that records being started, stops on SIGTERM and answers the ping.

    It never opens a socket: it only speaks the sidecar's JSON protocol on stdin and stdout, so a
    driver test can prove whether the child was spawned at all. It advertises "resolve" and answers
    `resolve_channel` with the channel the caller expected, because the driver refuses to go any
    further without an SDP answer; the answer here is fixed and offline, so nothing is resolved for
    real and no channel is guessed.
    """
    python_stub = os.path.join(bin_dir, "python3")
    with open(python_stub, "w", encoding="utf-8") as handle:
        handle.write(
            f"#!{sys.executable}\n"
            "import json, os, signal, sys\n"
            f"open({started_marker!r}, 'w').write(str(os.getpid()))\n"
            "def stop(signum, frame):\n"
            f"    open({stopped_marker!r}, 'w').write('stopped')\n"
            "    raise SystemExit(0)\n"
            "signal.signal(signal.SIGTERM, stop)\n"
            "for line in sys.stdin:\n"
            "    command = json.loads(line)\n"
            "    response = {'id': command.get('id'), 'ok': True,\n"
            "                'capabilities': ['connect', 'write', 'resolve']}\n"
            "    if command.get('cmd') == 'connect':\n"
            "        response.update({'address': 'XX:XX:XX:XX:EE:FF', 'channel': command.get('channel')})\n"
            "    if command.get('cmd') == 'resolve_channel':\n"
            "        response.update({'method': 'sdptool', 'channel': command.get('expect_channel', 18),\n"
            "                        'matched_uuid': True, 'matched_serial': False})\n"
            "    if command.get('cmd') == 'connect' and os.environ.get('BCS_TEST_CLOSE_AFTER_CONNECT') == '1':\n"
            "        print(json.dumps(response), flush=True)\n"
            "        break\n"
            "    print(json.dumps(response), flush=True)\n"
        )
    os.chmod(python_stub, 0o700)
    return python_stub


def write_sdp_only_sidecar_stub(bin_dir, started_marker, commands_marker):
    """A stand-in for python3 that behaves as the sidecar only when it is asked to be.

    The driver spawns `python3 <sidecar> --config ... --emit-hex`, while the shell also uses python3
    for its stream masker. So every other call is handed straight to the real interpreter, and only
    the sidecar path speaks the JSON protocol. It records each command it was asked for, which is how
    a test proves that the lookup asked for a resolve and nothing else, and it never opens a socket:
    the SDP answer is fixed and offline.
    """
    stub = os.path.join(bin_dir, "python3")
    script = '''#!%(real)s
import json, os, sys
REAL = %(real)r
if not any(argument.endswith("rfcomm_sidecar.py") for argument in sys.argv[1:]):
    os.execv(REAL, [REAL] + sys.argv[1:])
open(%(started)r, "w").write(str(os.getpid()))
capabilities = os.environ.get("BCS_TEST_CAPABILITIES", "connect,write,resolve").split(",")
channel = int(os.environ.get("BCS_TEST_SDP_CHANNEL", "18"))
refusal = os.environ.get("BCS_TEST_SDP_CODE", "")
for line in sys.stdin:
    command = json.loads(line)
    with open(%(commands)r, "a") as log:
        log.write(str(command.get("cmd")) + "\\n")
    response = {"id": command.get("id"), "ok": True}
    if command.get("cmd") == "ping":
        response["capabilities"] = capabilities
    elif refusal:
        response.update({"ok": False, "code": refusal, "errno": None,
                         "error": "the watch did not answer SDP"})
    else:
        response.update({"address": "XX:XX:XX:XX:EE:FF", "method": "sdptool", "channel": channel,
                         "matched_uuid": True, "matched_serial": False,
                         "detail": os.environ.get("BCS_TEST_SDP_DETAIL", "synthetic SDP evidence")})
    print(json.dumps(response), flush=True)
''' % {"real": sys.executable, "started": started_marker, "commands": commands_marker}
    with open(stub, "w", encoding="utf-8") as handle:
        handle.write(script)
    os.chmod(stub, 0o700)
    return stub


def run_on_pty(argv, env, respond=None, timeout=30):
    """Run argv on a pseudo-terminal, calling respond(master, text) after every read.

    Returns (exited, status, output). A child that outlives the deadline is killed, so a stuck
    prompt fails a test instead of hanging the suite. The deadline is generous because Node's cold
    start on a busy machine can take seconds; a real hang still fails, just later. Nothing here
    opens a network connection.
    """
    pid, master = pty.fork()
    if pid == 0:
        os.execve(argv[0], argv, env)
    output = bytearray()
    exited = False
    status = None
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    output.extend(os.read(master, 4096))
                except OSError:
                    pass
            if respond is not None:
                respond(master, output.decode("utf-8", "replace"))
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                exited = True
                break
    finally:
        if not exited:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        os.close(master)
    return exited, status, output


class ProbeChannelSpecTest(unittest.TestCase):
    def test_a_range_a_list_and_a_single_channel_all_work(self):
        self.assertEqual([1, 2, 3, 4, 5], probe.parse_channels("1-5"))
        self.assertEqual([2, 7], probe.parse_channels("2, 7"))
        self.assertEqual([9], probe.parse_channels("9"))

    def test_duplicates_are_sorted_out(self):
        self.assertEqual([3, 5], probe.parse_channels("5,3,5,3"))

    def test_a_channel_outside_rfcomm_is_refused(self):
        for spec in ("0", "31", "1-40", "-1", "abc", "1-"):
            with self.assertRaises(Exception) as caught:
                probe.parse_channels(spec)
            self.assertEqual("bad-config", getattr(caught.exception, "code", None), spec)

    def test_an_empty_spec_is_refused_rather_than_probing_nothing(self):
        with self.assertRaises(Exception) as caught:
            probe.parse_channels(" , ")
        self.assertEqual("bad-config", getattr(caught.exception, "code", None))

    def test_the_sdp_answer_is_probed_first_and_not_repeated(self):
        sdp = bcs_bt.SdpResult("sdptool", 5, "sdptool reported it")
        channels, spec = probe.ordered_channels([1, 2, 3, 5], sdp)
        self.assertEqual([5, 1, 2, 3], channels)
        self.assertIn("5 first", spec)

    def test_without_an_sdp_answer_the_requested_order_is_used(self):
        sdp = bcs_bt.SdpResult("unavailable", None, "no tools")
        channels, spec = probe.ordered_channels([1, 2, 3], sdp)
        self.assertEqual([1, 2, 3], channels)
        self.assertEqual("1-30", spec)


class ProbeChannelMainTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = os.path.join(self.directory.name, "watch.json")

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = probe.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_without_a_saved_address_it_stops_before_the_radio(self):
        code, out, err = self.run_main(["--config", self.config, "--channels", "1-3"])
        self.assertEqual(2, code)
        self.assertIn("no saved watch address", err)
        self.assertEqual("", out)

    def test_with_a_saved_address_sdp_only_connects_to_nothing(self):
        bcs_bt.save_watch_address(ADDRESS, self.config)
        code, out, _ = self.run_main(["--config", self.config, "--sdp-only", "--no-sdp"])
        self.assertEqual(1, code)
        self.assertIn("channel: none", out)
        self.assertIn("result: refused", out)
        self.assertIn("sdp: skipped", out)
        self.assertIn("masked_address: XX:XX:XX:XX:EE:FF", out)
        self.assertNotIn(ADDRESS, out)
        self.assertIn("--sdp-only was used", out)

    def test_json_output_is_one_object_with_no_full_address(self):
        bcs_bt.save_watch_address(ADDRESS, self.config)
        code, out, _ = self.run_main(["--config", self.config, "--sdp-only", "--no-sdp", "--json"])
        self.assertEqual(1, code)
        payload = json.loads(out.strip())
        self.assertEqual("XX:XX:XX:XX:EE:FF", payload["masked_address"])
        self.assertIsNone(payload["channel"])
        self.assertFalse(payload["accepted"])
        self.assertTrue(payload["next"].startswith("next: "))
        self.assertNotIn(ADDRESS, out)

    def test_an_unusable_channel_spec_is_a_config_error_not_a_probe(self):
        bcs_bt.save_watch_address(ADDRESS, self.config)
        code, out, err = self.run_main(["--config", self.config, "--channels", "99"])
        self.assertEqual(2, code)
        self.assertIn("99", err)
        self.assertEqual("", out)


class WatchAddressListTest(unittest.TestCase):
    def test_the_bluez_cache_is_parsed_and_every_address_is_masked(self):
        def runner(argv, **kwargs):  # noqa: ARG001
            return watch_tool.subprocess.CompletedProcess(
                argv,
                0,
                stdout=(
                    f"Device {ADDRESS} HUAWEI WATCH GT 5\n"
                    "Device 11:22:33:44:55:66 Some Speaker\n"
                    "not a device line\n"
                    "Device nonsense No Address\n"
                ),
                stderr="",
            )

        devices, note = watch_tool._bluetoothctl_devices(runner=runner)
        self.assertIsNone(note)
        self.assertEqual(
            [("XX:XX:XX:XX:EE:FF", "HUAWEI WATCH GT 5"), ("XX:XX:XX:XX:55:66", "Some Speaker")], devices
        )
        self.assertNotIn(ADDRESS, json.dumps(devices))

    def test_a_device_with_no_name_is_still_listed(self):
        def runner(argv, **kwargs):  # noqa: ARG001
            return watch_tool.subprocess.CompletedProcess(argv, 0, stdout=f"Device {ADDRESS}\n", stderr="")

        devices, _ = watch_tool._bluetoothctl_devices(runner=runner)
        self.assertEqual([("XX:XX:XX:XX:EE:FF", "(no name)")], devices)

    def test_a_missing_bluetoothctl_is_explained_rather_than_crashing(self):
        def runner(argv, **kwargs):  # noqa: ARG001
            raise FileNotFoundError("bluetoothctl")

        devices, note = watch_tool._bluetoothctl_devices(runner=runner)
        self.assertEqual([], devices)
        self.assertIn("bluetoothctl was not found", note)

    def test_a_hanging_bluetoothctl_does_not_hang_the_tool(self):
        def runner(argv, **kwargs):  # noqa: ARG001
            raise watch_tool.subprocess.TimeoutExpired("bluetoothctl", 15)

        devices, note = watch_tool._bluetoothctl_devices(runner=runner)
        self.assertEqual([], devices)
        self.assertIn("did not answer", note)

    def test_listing_marks_the_watch_and_keeps_the_output_safe_to_paste(self):
        self.swap_devices([("XX:XX:XX:XX:EE:FF", "HUAWEI WATCH GT 5")])
        lines = []
        code = watch_tool.cmd_list(None, out=lines.append)
        self.assertEqual(0, code)
        text = "\n".join(lines)
        self.assertIn("XX:XX:XX:XX:EE:FF  HUAWEI WATCH GT 5  <- looks like the watch", text)
        self.assertIn("tools/watch-address.py save", text)

    def test_an_empty_cache_tells_the_user_what_to_run_next(self):
        self.swap_devices([])
        lines = []
        code = watch_tool.cmd_list(None, out=lines.append)
        self.assertEqual(1, code)
        self.assertIn("bluetoothctl scan on", "\n".join(lines))

    def swap_devices(self, devices):
        original = watch_tool._bluetoothctl_devices
        watch_tool._bluetoothctl_devices = lambda: (devices, None)
        self.addCleanup(setattr, watch_tool, "_bluetoothctl_devices", original)


class WatchAddressSaveTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = os.path.join(self.directory.name, "watch.json")

class BcsAuthExitStatusTest(unittest.TestCase):
    def test_driver_status_is_preserved_in_pin_and_no_pin_branches(self):
        with tempfile.TemporaryDirectory() as directory:
            helper = os.path.join(directory, "helper")
            tools = os.path.join(helper, "tools")
            sidecar_dir = os.path.join(helper, "sidecar")
            state_home = os.path.join(directory, "state")
            bin_dir = os.path.join(directory, "bin")
            os.makedirs(tools)
            os.makedirs(sidecar_dir)
            os.makedirs(bin_dir)

            driver = os.path.join(tools, "bcs_auth.mjs")
            with open(driver, "w", encoding="utf-8") as handle:
                handle.write("// synthetic test driver\n")
            sidecar = os.path.join(sidecar_dir, "rfcomm_sidecar.py")
            with open(sidecar, "w", encoding="utf-8") as handle:
                handle.write(
                    "import json, sys\n"
                    "import os\n"
                    "for line in sys.stdin:\n"
                    "    command = json.loads(line)\n"
                    "    capabilities = os.environ.get('BCS_TEST_CAPABILITIES', 'connect,write,resolve').split(',')\n"
                    "    print(json.dumps({'id': command.get('id'), 'ok': True, 'capabilities': capabilities}), flush=True)\n"
                )

            node = os.path.join(bin_dir, "node")
            with open(node, "w", encoding="utf-8") as handle:
                handle.write(
                    "#!/bin/sh\n"
                    "case \"$1\" in\n"
                    "  -p) case \"$2\" in *process.versions.node*) echo 26.0.0 ;; *) echo strip ;; esac ;;\n"
                    "  --check) exit 0 ;;\n"
                    # The pin branch, only when the wrapper said it prompted. What arrived on stdin is
                    # saved to the marker, so the test can prove the pipe worked, and only its LENGTH
                    # is printed: the pin itself never reaches stdout, this run's log or its report.
                    "  *) if [ \"${BCS_PIN_PROMPT:-}\" = \"1\" ] && [ -n \"${BCS_TEST_STDIN_MARKER:-}\" ]; then\n"
                    "       IFS= read -r pin_line || pin_line=''\n"
                    "       printf '%s' \"$pin_line\" > \"$BCS_TEST_STDIN_MARKER\"\n"
                    "       printf 'synthetic driver read %s characters from stdin\\n' \"${#pin_line}\"\n"
                    "     fi\n"
                    "     printf 'synthetic driver output\\n'; exit \"${BCS_TEST_DRIVER_STATUS:-0}\" ;;\n"
                    "esac\n"
                )
            os.chmod(node, 0o700)

            key_file = os.path.join(directory, "synthetic-key")
            with open(key_file, "w", encoding="utf-8"):
                pass
            os.chmod(key_file, 0o600)
            script = os.path.join(HELPER, "tools", "bcs_auth.sh")
            state_dir = os.path.join(state_home, "aether-bcs")
            # Every run below writes into the same state directory, so the set of logs is how the
            # "one per run, never overwritten" rule is checked rather than promised.
            runs = set()

            for mode, pin_args, expect_prompt in (
                # (mode, extra flags, should the wrapper prompt here?)
                # The default auth-then-bind run must NOT prompt: the watch sends the pin code.
                ("bind", (), False),
                ("auth-then-bind", (), False),
                ("auth-then-bind", ("--pin",), True),
            ):
                for driver_status in (1, 3, 4):
                    with self.subTest(mode=mode, args=pin_args, driver_status=driver_status):
                        # Default auth-then-bind must pass its shell precondition with no key file.
                        if mode == "auth-then-bind" and os.path.exists(key_file):
                            os.unlink(key_file)
                        elif mode == "bind" and not os.path.exists(key_file):
                            with open(key_file, "w", encoding="utf-8"):
                                pass
                            os.chmod(key_file, 0o600)
                        stdin_marker = os.path.join(directory, "stdin-%s-%s-%s" % (mode, bool(pin_args), driver_status))
                        env = os.environ.copy()
                        env.update(
                            {
                                "PATH": bin_dir + os.pathsep + env["PATH"],
                                "BCS_AUTH_KEY_FILE": key_file,
                                "BCS_CONFIG_DIR": os.path.join(directory, "unused-config"),
                                "BCS_TEST_DRIVER_STATUS": str(driver_status),
                                "BCS_TEST_STDIN_MARKER": stdin_marker,
                                "XDG_STATE_HOME": state_home,
                            }
                        )
                        master, slave = pty.openpty()
                        process = subprocess.Popen(
                            ["bash", script, "--mode", mode, *pin_args, "--helper", helper],
                            stdin=slave,
                            stdout=slave,
                            stderr=slave,
                            env=env,
                            close_fds=True,
                        )
                        os.close(slave)
                        output = bytearray()
                        sent_pin = False
                        deadline = time.monotonic() + 10
                        try:
                            while process.poll() is None and time.monotonic() < deadline:
                                ready, _, _ = select.select([master], [], [], 0.1)
                                if ready:
                                    try:
                                        output.extend(os.read(master, 4096))
                                    except OSError:
                                        break
                                if expect_prompt and not sent_pin and b"pin code for this auth-then-bind run" in output:
                                    os.write(master, b"1234\n")
                                    sent_pin = True
                                if not expect_prompt and b"pin code for this auth-then-bind run" in output:
                                    # Without --pin a run must never wait for a pin: the watch is asked
                                    # for its own pin code instead. A prompt here is the regression.
                                    self.fail("the wrapper prompted for a pin without --pin")
                            return_code = process.wait(timeout=1)
                        finally:
                            os.close(master)
                            if process.poll() is None:
                                process.kill()
                                process.wait()
                        text = output.decode("utf-8", "replace")
                        self.assertEqual(driver_status, return_code, text)
                        self.assertNotIn("authenticated:", text)
                        # The pin path is opt-in: with --pin the typed digits really reach the driver's
                        # stdin, and without it nothing is piped and nothing is read.
                        if expect_prompt:
                            self.assertTrue(sent_pin, text)
                            with open(stdin_marker, encoding="utf-8") as handle:
                                self.assertEqual("1234", handle.read())
                            self.assertIn("synthetic driver read 4 characters from stdin", text)
                        else:
                            self.assertFalse(os.path.exists(stdin_marker), text)
                            self.assertNotIn("synthetic driver read", text)
                        state_dir = os.path.join(state_home, "aether-bcs")
                        self.assertEqual(0o700, stat.S_IMODE(os.stat(state_dir).st_mode))
                        # Exactly one new log per run, named by the UTC stamp and the pid, and every
                        # earlier run's log still there: a run can never overwrite the evidence of the
                        # run before it, which is what the first live bind needed.
                        current = {name for name in os.listdir(state_dir) if name.startswith("auth-run-")}
                        added = current - runs
                        self.assertEqual(1, len(added), sorted(current))
                        log_name = added.pop()
                        self.assertRegex(log_name, r"^auth-run-\d{8}T\d{6}Z-\d+\.log$")
                        with open(os.path.join(state_dir, log_name), encoding="utf-8") as handle:
                            logged = handle.read()
                        # The log carries what the driver printed, and for a typed pin that is the
                        # *count* of characters it read off stdin: the digits reached the driver's
                        # stdin (the marker above proves it) and never its output.
                        self.assertIn("synthetic driver output", logged)
                        if expect_prompt:
                            self.assertIn("synthetic driver read 4 characters from stdin", logged)
                        else:
                            self.assertNotIn("synthetic driver read", logged)
                        self.assertEqual(runs, runs & current, sorted(current))
                        for name in sorted(current):
                            self.assertEqual(0o600, stat.S_IMODE(os.stat(os.path.join(state_dir, name)).st_mode))
                        runs = current



class BcsAuthSdpOnlyTest(unittest.TestCase):
    """--sdp-only: the channel lookup, with a stub sidecar and no radio.

    The stub python3 on PATH answers the driver's ping and resolve_channel and records every command
    it was asked for, so "no connect and no write was requested" is a fact read from the stub's own
    log rather than a promise. No key file exists in any of these runs: a run that read one would stop
    with "cannot read the auth key file", so exit 0 proves the key was never touched.
    """

    def run_lookup(
        self,
        directory,
        typed="SDPLOOKUP",
        extra_args=(),
        capabilities="connect,write,resolve",
        refusal="",
        channel=18,
        timeout=60,
        extra_env=None,
    ):
        bin_dir = os.path.join(directory, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        state_home = os.path.join(directory, "state-home")
        state_dir = os.path.join(state_home, "aether-bcs")
        started = os.path.join(directory, "sidecar-started")
        commands = os.path.join(directory, "sidecar-commands")
        write_sdp_only_sidecar_stub(bin_dir, started, commands)
        key_file = os.path.join(directory, "no-such-key")
        env = os.environ.copy()
        env.update(
            {
                "PATH": bin_dir + os.pathsep + env["PATH"],
                # A sandboxed home and config home, so nothing this run does can reach a real key,
                # a real account file or a real watch address even by accident.
                "HOME": directory,
                "XDG_CONFIG_HOME": os.path.join(directory, "config-home"),
                "BCS_AUTH_KEY_FILE": key_file,
                "BCS_CONFIG_DIR": os.path.join(directory, "unused-config"),
                "XDG_STATE_HOME": state_home,
                "BCS_TEST_CAPABILITIES": capabilities,
                "BCS_TEST_SDP_CODE": refusal,
                "BCS_TEST_SDP_CHANNEL": str(channel),
            }
        )
        env.update(extra_env or {})
        script = os.path.join(HELPER, "tools", "bcs_auth.sh")
        # run_on_pty() uses execve(), which does not search PATH, so the interpreter needs its full
        # path here.
        shell = shutil.which("bash")
        self.assertIsNotNone(shell, "bash is required for the shell-level lookup tests")
        sent = set()

        def respond(master, text):
            if "confirmation" not in sent and "type SDPLOOKUP to continue:" in text:
                os.write(master, (typed + "\n").encode())
                sent.add("confirmation")

        exited, status, output = run_on_pty(
            [shell, script, "--sdp-only", *extra_args], env, respond, timeout=timeout
        )
        text = output.decode("utf-8", "replace")
        self.assertTrue(exited, text)
        reports = []
        if os.path.isdir(state_dir):
            reports = sorted(name for name in os.listdir(state_dir) if name.startswith("auth-report-"))
        asked = []
        if os.path.exists(commands):
            with open(commands, encoding="utf-8") as handle:
                asked = [line.strip() for line in handle if line.strip()]
        return os.waitstatus_to_exitcode(status), text, asked, reports, state_dir, started

    def read_report(self, state_dir, name):
        with open(os.path.join(state_dir, name), encoding="utf-8") as handle:
            return handle.read()

    def test_the_lookup_prints_the_masked_evidence_and_never_opens_a_link(self):
        with tempfile.TemporaryDirectory() as directory:
            status, text, asked, reports, state_dir, started = self.run_lookup(directory)
            self.assertEqual(0, status, text)
            # The gate is the lookup's own word, and it is not the handshake's.
            self.assertIn("type SDPLOOKUP to continue:", text)
            self.assertNotIn("type AUTHENTICATE to continue:", text)
            self.assertIn("watch: XX:XX:XX:XX:EE:FF (masked)", text)
            self.assertIn(f"service uuid: {bcs_bt.HUAWEI_SDP_UUID}", text)
            self.assertIn("method: sdptool", text)
            self.assertIn("channel: 18", text)
            self.assertIn("evidence: huawei uuid: yes, serial record: no", text)
            self.assertIn("saved channel: 18 (matches: yes)", text)
            self.assertIn("result: resolved", text)
            # Exactly two commands reached the sidecar: the ping and the resolve. No connect, no write.
            self.assertEqual(["ping", "resolve_channel"], asked)
            self.assertTrue(os.path.exists(started), "the stub sidecar was never started")
            # No key file exists at the path the run was given, so reaching exit 0 proves it was never
            # read; and a lookup must not create the run identity either.
            self.assertFalse(os.path.exists(os.path.join(directory, "no-such-key")))
            self.assertFalse(
                os.path.exists(os.path.join(state_dir, "identity.json")),
                "a lookup must not create the run identity",
            )
            # One report for this run, named by stamp and pid, private, and carrying the evidence.
            self.assertEqual(1, len(reports), reports)
            self.assertRegex(reports[0], r"^auth-report-\d{8}T\d{6}Z-\d+\.txt$")
            report = os.path.join(state_dir, reports[0])
            self.assertEqual(0o600, stat.S_IMODE(os.stat(report).st_mode))
            body = self.read_report(state_dir, reports[0])
            self.assertIn("mode: sdp-only", body)
            self.assertIn("channel: 18", body)
            self.assertIn("XX:XX:XX:XX:EE:FF", body)
            self.assertIn("stage: sdp-resolved", body)
            # The log is this run's own file, private as well, and masked like every other run.
            logs = sorted(name for name in os.listdir(state_dir) if name.startswith("auth-run-"))
            self.assertEqual(1, len(logs), logs)
            self.assertEqual(0o600, stat.S_IMODE(os.stat(os.path.join(state_dir, logs[0])).st_mode))
            with open(os.path.join(state_dir, logs[0]), encoding="utf-8") as handle:
                self.assertIn("channel: 18", handle.read())

    def test_a_word_other_than_sdplookup_starts_nothing(self):
        for word in ("AUTHENTICATE", "sdp", ""):
            with self.subTest(word=word):
                with tempfile.TemporaryDirectory() as directory:
                    status, text, asked, reports, _state, started = self.run_lookup(directory, typed=word)
                    self.assertEqual(2, status, text)
                    self.assertIn("not confirmed", text)
                    self.assertIn("SDP was asked nothing", text)
                    self.assertEqual([], asked, "nothing may reach the sidecar without the word")
                    self.assertFalse(os.path.exists(started), "no sidecar may start without the word")
                    self.assertEqual([], reports, "a refused lookup writes no report")

    def test_an_sdp_refusal_keeps_its_code_and_is_reported(self):
        for code in ("sdp-unavailable", "sdp-no-channel", "sdp-unconfirmed"):
            with self.subTest(code=code):
                with tempfile.TemporaryDirectory() as directory:
                    status, text, asked, reports, state_dir, _started = self.run_lookup(directory, refusal=code)
                    self.assertEqual(2, status, text)
                    self.assertIn(f"refused: {code}", text)
                    self.assertIn("no channel is proven", text)
                    self.assertNotIn("result: resolved", text)
                    # The resolve was asked for and nothing else: no connect, so no socket.
                    self.assertEqual(["ping", "resolve_channel"], asked)
                    self.assertEqual(1, len(reports), reports)
                    body = self.read_report(state_dir, reports[0])
                    self.assertIn("mode: sdp-only", body)
                    self.assertIn(code, body)

    def test_a_sidecar_without_resolve_is_blocked_before_anything_is_asked(self):
        with tempfile.TemporaryDirectory() as directory:
            status, text, asked, reports, state_dir, _started = self.run_lookup(
                directory, capabilities="connect,write"
            )
            self.assertEqual(3, status, text)
            self.assertIn("did not advertise resolve", text)
            # Only the ping: no resolve was asked, because the answer was already known to be useless.
            self.assertEqual(["ping"], asked)
            self.assertEqual(1, len(reports), reports)
            self.assertIn("blocked", self.read_report(state_dir, reports[0]))

    def test_a_channel_other_than_the_saved_one_is_a_disagreement(self):
        with tempfile.TemporaryDirectory() as directory:
            status, text, asked, reports, state_dir, _started = self.run_lookup(directory, channel=7)
            self.assertEqual(2, status, text)
            self.assertIn("channel: 7", text)
            self.assertIn("saved channel: 18 (matches: no)", text)
            self.assertIn("refused: sdp-disagreement", text)
            self.assertEqual(["ping", "resolve_channel"], asked)
            body = self.read_report(state_dir, reports[0])
            self.assertIn("sdp-disagreement", body)
            self.assertIn("saved channel: 18 (matches: no)", body)

    def test_flags_that_would_read_a_key_or_send_a_frame_are_refused(self):
        script = os.path.join(HELPER, "tools", "bcs_auth.sh")
        cases = (
            (("--with-account",), "--with-account"),
            (("--save-derived",), "--save-derived"),
            (("--set-key",), "--set-key"),
            (("--set-account",), "--set-account"),
            (("--self-test",), "--self-test"),
            # Phase 3G: a lookup opens no link and sends no frame, so the link options and the model
            # string have nothing to apply to and are refused rather than ignored.
            (("--bt-security", "medium"), "--bt-security"),
            (("--require-bond",), "--require-bond"),
            (("--phone-model", "Pixel 7"), "--phone-model"),
            # --pin feeds an auth-then-bind run, and a lookup is not one: there is no link to send a
            # pin code on, so it is refused rather than read and thrown away.
            (("--pin",), "--pin"),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                with tempfile.TemporaryDirectory() as directory:
                    env = os.environ.copy()
                    env["HOME"] = directory
                    env["XDG_CONFIG_HOME"] = os.path.join(directory, "config-home")
                    env["XDG_STATE_HOME"] = os.path.join(directory, "state")
                    env["BCS_AUTH_KEY_FILE"] = os.path.join(directory, "no-key")
                    result = subprocess.run(
                        ["bash", script, "--sdp-only", *args],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=60,
                    )
                    self.assertEqual(2, result.returncode, result.stdout + result.stderr)
                    self.assertIn(expected, result.stderr)
                    # Refused before anything was created or read.
                    self.assertFalse(os.path.exists(os.path.join(directory, "state", "aether-bcs")))
                    self.assertFalse(os.path.exists(os.path.join(directory, "no-key")))

    def test_without_a_terminal_it_refuses_before_anything_starts(self):
        # The gate is not only the word: a lookup with no terminal cannot be confirmed at all, so it
        # must refuse before it creates a state directory, reads a key or starts a sidecar.
        script = os.path.join(HELPER, "tools", "bcs_auth.sh")
        with tempfile.TemporaryDirectory() as directory:
            env = os.environ.copy()
            env["HOME"] = directory
            env["XDG_CONFIG_HOME"] = os.path.join(directory, "config-home")
            env["XDG_STATE_HOME"] = os.path.join(directory, "state")
            env["BCS_AUTH_KEY_FILE"] = os.path.join(directory, "no-key")
            result = subprocess.run(
                ["bash", script, "--sdp-only"], capture_output=True, text=True, env=env, timeout=60
            )
            self.assertEqual(2, result.returncode, result.stdout + result.stderr)
            self.assertIn("run this in your own terminal", result.stderr)
            self.assertFalse(os.path.exists(os.path.join(directory, "state", "aether-bcs")))

    def test_help_and_plan_document_the_lookup_and_its_word(self):
        script = os.path.join(HELPER, "tools", "bcs_auth.sh")
        with tempfile.TemporaryDirectory() as directory:
            env = os.environ.copy()
            env["HOME"] = directory
            env["XDG_CONFIG_HOME"] = os.path.join(directory, "config-home")
            env["XDG_STATE_HOME"] = os.path.join(directory, "state")
            env["BCS_AUTH_KEY_FILE"] = os.path.join(directory, "no-key")
            helped = subprocess.run(
                ["bash", script, "--help"], capture_output=True, text=True, env=env, timeout=60
            )
            self.assertEqual(0, helped.returncode, helped.stdout + helped.stderr)
            self.assertIn("--sdp-only", helped.stdout)
            self.assertIn("SDPLOOKUP", helped.stdout)
            # The help has to say what the mode does not do, not only that it exists.
            self.assertIn("before opening any RFCOMM connection", helped.stdout)
            self.assertIn("before reading the", helped.stdout)
            planned = subprocess.run(
                ["bash", script, "--plan", "--sdp-only"],
                capture_output=True,
                text=True,
                env=env,
                timeout=120,
            )
            self.assertEqual(0, planned.returncode, planned.stdout + planned.stderr)
            self.assertIn("SDPLOOKUP", planned.stdout)
            self.assertIn("NOT read the auth key", planned.stdout)
            self.assertIn("before opening any RFCOMM connection", planned.stdout)
            self.assertIn("auth-report-", planned.stdout)
            # --plan writes nothing, for either mode.
            self.assertFalse(os.path.exists(os.path.join(directory, "state", "aether-bcs")))


class BcsAuthLinkOptionsTest(unittest.TestCase):
    """Phase 3G: --bt-security, --require-bond and --phone-model, from flag to environment.

    Nothing here opens a radio: the driver is run directly for its own validation, and the shell is
    run for its flag handling and --plan. Every run is sandboxed into a temporary HOME, so a real key,
    account or watch address is out of reach.
    """

    def sandbox(self, directory):
        env = os.environ.copy()
        env["HOME"] = directory
        env["XDG_CONFIG_HOME"] = os.path.join(directory, "config-home")
        env["XDG_STATE_HOME"] = os.path.join(directory, "state")
        env["BCS_AUTH_KEY_FILE"] = os.path.join(directory, "no-key")
        env["BCS_STATE_DIR"] = os.path.join(directory, "state", "aether-bcs")
        return env

    def run_driver(self, env, extra=()):
        node = shutil.which("node")
        self.assertIsNotNone(node, "node is required for the driver-level option tests")
        driver = os.path.join(HELPER, "tools", "bcs_auth.mjs")
        return subprocess.run(
            [node, driver, *extra], capture_output=True, text=True, env=env, timeout=60
        )

    def test_the_driver_refuses_the_link_options_when_only_a_lookup_was_asked_for(self):
        cases = (
            ({"BCS_BT_SECURITY": "medium"}, "--bt-security"),
            ({"BCS_REQUIRE_BOND": "1"}, "--require-bond"),
            ({"BCS_PHONE_MODEL": "Pixel 7"}, "--phone-model"),
            # The same for the pin code: --sdp-only sends no frame, so a pin has nowhere to go.
            ({"BCS_PIN_PROMPT": "1"}, "--pin"),
        )
        for extra_env, expected in cases:
            with self.subTest(extra_env=extra_env):
                with tempfile.TemporaryDirectory() as directory:
                    env = self.sandbox(directory)
                    env.update({"BCS_SDP_ONLY": "1", **extra_env})
                    result = self.run_driver(env)
                    self.assertEqual(2, result.returncode, result.stdout + result.stderr)
                    self.assertIn(expected, result.stdout)
                    self.assertIn("belong to a live run", result.stdout)
                    self.assertIn("opens no RFCOMM connection", result.stdout)

    def test_the_driver_refuses_an_unknown_level_and_a_bad_model_before_anything_starts(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.sandbox(directory)
            env["BCS_BT_SECURITY"] = "fips"
            bad_level = self.run_driver(env)
            self.assertEqual(2, bad_level.returncode, bad_level.stdout + bad_level.stderr)
            self.assertIn("none, low, medium, high", bad_level.stdout)
        for model in ("x" * 33, "tab\there"):
            with self.subTest(model=model):
                with tempfile.TemporaryDirectory() as directory:
                    env = self.sandbox(directory)
                    env["BCS_PHONE_MODEL"] = model
                    result = self.run_driver(env)
                    self.assertEqual(2, result.returncode, result.stdout + result.stderr)
                    self.assertIn("1-32 printable ASCII", result.stdout)


    def test_the_driver_refuses_a_typed_pin_for_an_operation_that_never_uses_one(self):
        # A pin belongs to the auth-then-bind operation: the bind operation keys its handshake from
        # the stored key. The shell refuses this too; the driver says it in its own words, before the
        # terminal gate, before the key is read and before any state directory exists.
        with tempfile.TemporaryDirectory() as directory:
            env = self.sandbox(directory)
            env["BCS_PIN_PROMPT"] = "1"
            result = self.run_driver(env)
            self.assertEqual(2, result.returncode, result.stdout + result.stderr)
            self.assertIn("BCS_PIN_PROMPT", result.stdout)
            self.assertIn("only --mode auth-then-bind uses", result.stdout)
            self.assertFalse(os.path.exists(os.path.join(directory, "state", "aether-bcs")))

    def test_help_and_plan_document_where_the_pin_code_comes_from(self):
        # The pin code is the watch's in the default run and this terminal's only with --pin, and the
        # help and the plan have to say which is which: a run that waits for nothing must not look
        # like a run that waits for a pin.
        script = os.path.join(HELPER, "tools", "bcs_auth.sh")
        with tempfile.TemporaryDirectory() as directory:
            env = self.sandbox(directory)
            helped = subprocess.run(
                ["bash", script, "--help"], capture_output=True, text=True, env=env, timeout=60
            )
            self.assertEqual(0, helped.returncode, helped.stdout + helped.stderr)
            self.assertIn("--mode auth-then-bind", helped.stdout)
            self.assertIn("--pin", helped.stdout)
            self.assertIn("the watch's own reply", helped.stdout)

            default = subprocess.run(
                ["bash", script, "--plan", "--mode", "auth-then-bind"],
                capture_output=True,
                text=True,
                env=env,
                timeout=120,
            )
            self.assertEqual(0, default.returncode, default.stdout + default.stderr)
            self.assertIn("the pin code asked for from the watch itself", default.stdout)
            self.assertIn("read no auth key file", default.stdout)
            self.assertNotIn("  1. read the auth key", default.stdout)
            self.assertIn("no pin code is typed anywhere", default.stdout)

            typed = subprocess.run(
                ["bash", script, "--plan", "--mode", "auth-then-bind", "--pin"],
                capture_output=True,
                text=True,
                env=env,
                timeout=120,
            )
            self.assertEqual(0, typed.returncode, typed.stdout + typed.stderr)
            self.assertIn("the pin code read here at a hidden prompt (--pin)", typed.stdout)
            self.assertIn("the pin code comes from this terminal because --pin was given", typed.stdout)
            explicit = subprocess.run(
                ["bash", script, "--plan", "--mode", "auth-then-bind", "--key", env["BCS_AUTH_KEY_FILE"]],
                capture_output=True, text=True, env=env, timeout=120,
            )
            self.assertEqual(0, explicit.returncode, explicit.stdout + explicit.stderr)
            self.assertIn("  1. read the auth key", explicit.stdout)
            # --plan still writes nothing at all, with or without the pin flag.
            self.assertFalse(os.path.exists(os.path.join(directory, "state", "aether-bcs")))

    def test_the_shell_refuses_a_pin_without_the_operation_that_uses_it(self):
        # Two refusals the shell owns, both before anything is created: a pin with --mode bind, and a
        # pin with --sdp-only. Neither can be a run that quietly ignores the flag.
        script = os.path.join(HELPER, "tools", "bcs_auth.sh")
        cases = (
            (("--pin",), "--pin"),
            (("--mode", "auth-then-bind", "--pin", "--sdp-only"), "--pin"),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                with tempfile.TemporaryDirectory() as directory:
                    result = subprocess.run(
                        ["bash", script, *args, "--plan"],
                        capture_output=True,
                        text=True,
                        env=self.sandbox(directory),
                        timeout=60,
                    )
                    self.assertEqual(2, result.returncode, result.stdout + result.stderr)
                    self.assertIn(expected, result.stderr)
                    self.assertFalse(os.path.exists(os.path.join(directory, "state", "aether-bcs")))

    def test_the_shell_refuses_a_bad_value_before_anything_is_created(self):
        script = os.path.join(HELPER, "tools", "bcs_auth.sh")
        cases = (
            (("--bt-security", "fips"), "--bt-security"),
            (("--phone-model", "x" * 33), "--phone-model"),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                with tempfile.TemporaryDirectory() as directory:
                    result = subprocess.run(
                        ["bash", script, *args, "--plan"],
                        capture_output=True,
                        text=True,
                        env=self.sandbox(directory),
                        timeout=60,
                    )
                    self.assertEqual(2, result.returncode, result.stdout + result.stderr)
                    self.assertIn(expected, result.stderr)
                    self.assertFalse(os.path.exists(os.path.join(directory, "state", "aether-bcs")))

    def test_help_and_plan_document_the_three_options_and_the_defaults(self):
        script = os.path.join(HELPER, "tools", "bcs_auth.sh")
        with tempfile.TemporaryDirectory() as directory:
            env = self.sandbox(directory)
            helped = subprocess.run(
                ["bash", script, "--help"], capture_output=True, text=True, env=env, timeout=60
            )
            self.assertEqual(0, helped.returncode, helped.stdout + helped.stderr)
            for option in ("--bt-security", "--require-bond", "--phone-model"):
                self.assertIn(option, helped.stdout)
            # The help has to say what the options do not do, not only that they exist.
            self.assertIn("pairs a watch", helped.stdout)
            self.assertIn("NOT promise", helped.stdout)

            planned = subprocess.run(
                ["bash", script, "--plan"], capture_output=True, text=True, env=env, timeout=120
            )
            self.assertEqual(0, planned.returncode, planned.stdout + planned.stderr)
            self.assertIn("bt-security none, require-bond off", planned.stdout)

            chosen = subprocess.run(
                ["bash", script, "--plan", "--bt-security", "medium", "--require-bond",
                 "--phone-model", "Pixel 7"],
                capture_output=True,
                text=True,
                env=env,
                timeout=120,
            )
            self.assertEqual(0, chosen.returncode, chosen.stdout + chosen.stderr)
            self.assertIn("bt-security medium", chosen.stdout)
            self.assertIn("require-bond on", chosen.stdout)
            self.assertIn("Pixel 7", chosen.stdout)
            # --plan still writes nothing at all.
            self.assertFalse(os.path.exists(os.path.join(directory, "state", "aether-bcs")))

    def test_the_lookup_plan_says_the_options_are_not_accepted_there(self):
        script = os.path.join(HELPER, "tools", "bcs_auth.sh")
        with tempfile.TemporaryDirectory() as directory:
            planned = subprocess.run(
                ["bash", script, "--plan", "--sdp-only"],
                capture_output=True,
                text=True,
                env=self.sandbox(directory),
                timeout=120,
            )
            self.assertEqual(0, planned.returncode, planned.stdout + planned.stderr)
            self.assertIn("link options are not accepted here", planned.stdout)
            self.assertIn("opens nothing", planned.stdout)


class BcsAuthSetKeyTest(unittest.TestCase):
    synthetic_key = "c0ffee12"

    def run_tool(
        self,
        directory,
        subcommand,
        responses,
        existing=None,
        existing_mode=0o600,
        extra_args=(),
        symlink_to=None,
        filename="auth-key.txt",
        extra_env=None,
    ):
        """Run bcs_auth.sh on a pseudo-terminal and answer its prompts in order.

        `filename` is the file the subcommand writes; the key and the account live in two different
        files, so the same driver covers both. Nothing here reaches a watch.
        """
        config_dir = os.path.join(directory, "config")
        os.makedirs(config_dir, exist_ok=True)
        target_file = os.path.join(config_dir, filename)
        if symlink_to is not None:
            os.symlink(symlink_to, target_file)
        elif existing is not None:
            with open(target_file, "w", encoding="utf-8") as handle:
                handle.write(existing + "\n")
            os.chmod(target_file, existing_mode)

        env = os.environ.copy()
        env["BCS_CONFIG_DIR"] = config_dir
        if extra_env:
            env.update(extra_env)
        script = os.path.join(HELPER, "tools", "bcs_auth.sh")
        master, slave = pty.openpty()
        process = subprocess.Popen(
            ["bash", script, subcommand, *extra_args],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            close_fds=True,
        )
        os.close(slave)
        output = bytearray()
        sent = set()
        # 30 s, not 10: bash and a pty still finish in well under a second here, but a machine under
        # load must fail a hang rather than a slow start.
        deadline = time.monotonic() + 30
        try:
            while process.poll() is None and time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        output.extend(os.read(master, 4096))
                    except OSError:
                        break
                for index, (prompt, answer) in enumerate(responses):
                    if index not in sent and prompt in output:
                        os.write(master, answer + b"\n")
                        sent.add(index)
            return_code = process.wait(timeout=1)
        finally:
            os.close(master)
            if process.poll() is None:
                process.kill()
                process.wait()
        return return_code, output.decode("utf-8", "replace"), target_file, config_dir

    def run_set_key(self, directory, responses, **kwargs):
        return self.run_tool(directory, "--set-key", responses, **kwargs)

    def run_set_account(self, directory, responses, **kwargs):
        kwargs.setdefault("filename", "account.txt")
        return self.run_tool(directory, "--set-account", responses, **kwargs)

    def test_set_key_hidden_double_entry_writes_hex_with_private_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            key = self.synthetic_key.encode()
            status, output, key_file, config_dir = self.run_set_key(
                directory,
                [
                    (b"auth key in hexadecimal (hidden): ", key),
                    (b"repeat auth key (hidden): ", key),
                ],
            )
            self.assertEqual(0, status, output)
            self.assertNotIn(self.synthetic_key, output)
            with open(key_file, encoding="utf-8") as handle:
                self.assertEqual(f"{self.synthetic_key}\n", handle.read())
            self.assertEqual(0o700, stat.S_IMODE(os.stat(config_dir).st_mode))
            self.assertEqual(0o600, stat.S_IMODE(os.stat(key_file).st_mode))

    def test_existing_key_is_not_overwritten_without_exact_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            status, output, key_file, _ = self.run_set_key(
                directory,
                [(b"Type OVERWRITE to replace it: ", b"no")],
                existing="deadbeef",
            )
            self.assertEqual(2, status, output)
            self.assertNotIn("deadbeef", output)
            self.assertNotIn(self.synthetic_key, output)
            with open(key_file, encoding="utf-8") as handle:
                self.assertEqual("deadbeef\n", handle.read())

    def test_existing_key_can_only_be_replaced_after_overwrite_and_matching_hidden_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            key = self.synthetic_key.encode()
            status, output, key_file, _ = self.run_set_key(
                directory,
                [
                    (b"Type OVERWRITE to replace it: ", b"OVERWRITE"),
                    (b"auth key in hexadecimal (hidden): ", key),
                    (b"repeat auth key (hidden): ", key),
                ],
                existing="deadbeef",
                existing_mode=0o644,
            )
            self.assertEqual(0, status, output)
            self.assertNotIn(self.synthetic_key, output)
            self.assertNotIn("deadbeef", output)
            with open(key_file, encoding="utf-8") as handle:
                self.assertEqual(f"{self.synthetic_key}\n", handle.read())
            self.assertEqual(0o600, stat.S_IMODE(os.stat(key_file).st_mode))

    def test_set_key_rejects_mismatched_and_odd_length_entries_without_writing(self):
        cases = [
            ("c0ffee12", "c0ffee13"),
            ("abc", "abc"),
        ]
        for first, second in cases:
            with self.subTest(first_length=len(first), second_length=len(second)):
                with tempfile.TemporaryDirectory() as directory:
                    status, output, key_file, _ = self.run_set_key(
                        directory,
                        [
                            (b"auth key in hexadecimal (hidden): ", first.encode()),
                            (b"repeat auth key (hidden): ", second.encode()),
                        ],
                    )
                    self.assertEqual(2, status, output)
                    self.assertNotIn(first, output)
                    self.assertNotIn(second, output)
                    self.assertFalse(os.path.exists(key_file))

    def test_a_17_digit_account_id_is_refused_as_a_key_and_says_which_value_is_which(self):
        with tempfile.TemporaryDirectory() as directory:
            account = "12345678901234567"
            status, output, key_file, _ = self.run_set_key(
                directory,
                [
                    (b"auth key in hexadecimal (hidden): ", account.encode()),
                    (b"repeat auth key (hidden): ", account.encode()),
                ],
            )
            self.assertEqual(2, status, output)
            self.assertFalse(os.path.exists(key_file))
            self.assertNotIn(account, output)
            self.assertIn("hexadecimal", output)
            self.assertIn("account ID", output)

    def test_generate_writes_32_hex_characters_with_private_modes_and_never_shows_them(self):
        with tempfile.TemporaryDirectory() as directory:
            status, output, key_file, config_dir = self.run_set_key(directory, [], extra_args=("--generate",))
            self.assertEqual(0, status, output)
            with open(key_file, encoding="utf-8") as handle:
                generated = handle.read().strip()
            self.assertRegex(generated, r"^[0-9a-f]{32}$")
            self.assertEqual(16, len(bytes.fromhex(generated)))
            self.assertIn("key generated and saved", output)
            self.assertNotIn(generated, output)
            self.assertIsNone(re.search(r"[0-9a-f]{32}", output), "a 32-hex run appeared in the output")
            self.assertEqual(0o600, stat.S_IMODE(os.stat(key_file).st_mode))
            self.assertEqual(0o700, stat.S_IMODE(os.stat(config_dir).st_mode))

    def test_generate_does_not_replace_an_existing_key_without_the_overwrite_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            status, output, key_file, _ = self.run_set_key(
                directory,
                [(b"Type OVERWRITE to replace it: ", b"no")],
                existing="deadbeef",
                extra_args=("--generate",),
            )
            self.assertEqual(2, status, output)
            self.assertIn("not overwritten", output)
            self.assertIsNone(re.search(r"[0-9a-f]{32}", output))
            with open(key_file, encoding="utf-8") as handle:
                self.assertEqual("deadbeef\n", handle.read())

    def test_generate_replaces_an_existing_key_only_after_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            status, output, key_file, _ = self.run_set_key(
                directory,
                [(b"Type OVERWRITE to replace it: ", b"OVERWRITE")],
                existing="deadbeef",
                existing_mode=0o644,
                extra_args=("--generate",),
            )
            self.assertEqual(0, status, output)
            with open(key_file, encoding="utf-8") as handle:
                generated = handle.read().strip()
            self.assertRegex(generated, r"^[0-9a-f]{32}$")
            self.assertNotIn(generated, output)
            self.assertNotIn("deadbeef", output)
            self.assertEqual(0o600, stat.S_IMODE(os.stat(key_file).st_mode))

    def test_generate_refuses_to_write_through_a_symbolic_link(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "not-the-key-file")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("synthetic\n")
            status, output, key_file, _ = self.run_set_key(
                directory,
                [],
                extra_args=("--generate",),
                symlink_to=target,
            )
            self.assertEqual(2, status, output)
            self.assertIn("symbolic link", output)
            self.assertTrue(os.path.islink(key_file))
            with open(target, encoding="utf-8") as handle:
                self.assertEqual("synthetic\n", handle.read())

    def test_generate_without_set_key_is_refused_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            config_dir = os.path.join(directory, "config")
            os.makedirs(config_dir)
            env = os.environ.copy()
            env["BCS_CONFIG_DIR"] = config_dir
            script = os.path.join(HELPER, "tools", "bcs_auth.sh")
            result = subprocess.run(["bash", script, "--generate"], capture_output=True, env=env, text=True)
            output = result.stdout + result.stderr
            self.assertEqual(2, result.returncode, output)
            self.assertIn("belongs with --set-key", output)
            self.assertEqual([], os.listdir(config_dir))


class BcsAuthSetAccountTest(unittest.TestCase):
    """--set-account: the account file, its gates, and the value never leaving the file.

    Every value below is synthetic. The class borrows the pseudo-terminal driver from the key tests
    instead of inheriting them, so the key tests are not run twice.
    """

    run_tool = BcsAuthSetKeyTest.run_tool
    run_set_account = BcsAuthSetKeyTest.run_set_account
    account = "12345678901234567"  # 17 synthetic digits

    prompts = (
        b"Huawei account ID, 17-19 digits (hidden): ",
        b"repeat the account ID (hidden): ",
    )

    def written_prompts(self, value):
        return [
            (self.prompts[0], value.encode()),
            (self.prompts[1], value.encode()),
        ]

    def test_seventeen_digits_are_written_at_0600_in_a_0700_directory_and_never_shown(self):
        with tempfile.TemporaryDirectory() as directory:
            status, output, account_file, config_dir = self.run_set_account(
                directory, self.written_prompts(self.account)
            )
            self.assertEqual(0, status, output)
            with open(account_file, encoding="utf-8") as handle:
                self.assertEqual(f"{self.account}\n", handle.read())
            self.assertEqual(0o600, stat.S_IMODE(os.stat(account_file).st_mode))
            self.assertEqual(0o700, stat.S_IMODE(os.stat(config_dir).st_mode))
            self.assertIn("account ID saved", output)
            self.assertNotIn(self.account, output)
            self.assertFalse(os.path.exists(os.path.join(config_dir, "auth-key.txt")))

    def test_nineteen_digits_are_the_upper_bound_and_are_accepted(self):
        value = self.account + "89"
        self.assertEqual(19, len(value))
        with tempfile.TemporaryDirectory() as directory:
            status, output, account_file, _ = self.run_set_account(directory, self.written_prompts(value))
            self.assertEqual(0, status, output)
            with open(account_file, encoding="utf-8") as handle:
                self.assertEqual(f"{value}\n", handle.read())
            self.assertNotIn(value, output)

    def test_sixteen_and_twenty_digits_and_a_non_digit_are_refused_without_writing(self):
        cases = {
            "too short": "1234567890123456",       # 16 digits
            "too long": "12345678901234567890",   # 20 digits
            "not digits": "1234567890123456x",    # 17 characters, one letter
        }
        for name, value in cases.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    status, output, account_file, _ = self.run_set_account(
                        directory, self.written_prompts(value)
                    )
                    self.assertEqual(2, status, output)
                    self.assertFalse(os.path.exists(account_file))
                    self.assertNotIn(value, output)
                    if name == "not digits":
                        self.assertIn("digits only", output)
                    else:
                        self.assertIn("17 to 19 digits", output)

    def test_mismatched_entries_write_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            status, output, account_file, _ = self.run_set_account(
                directory,
                [
                    (self.prompts[0], self.account.encode()),
                    (self.prompts[1], (self.account + "8").encode()),
                ],
            )
            self.assertEqual(2, status, output)
            self.assertIn("did not match", output)
            self.assertFalse(os.path.exists(account_file))
            self.assertNotIn(self.account, output)

    def test_an_existing_account_is_kept_without_the_overwrite_word(self):
        with tempfile.TemporaryDirectory() as directory:
            status, output, account_file, _ = self.run_set_account(
                directory,
                [(b"Type OVERWRITE to replace it: ", b"no")],
                existing="98765432109876543",
            )
            self.assertEqual(2, status, output)
            self.assertIn("not overwritten", output)
            self.assertNotIn(self.account, output)
            with open(account_file, encoding="utf-8") as handle:
                self.assertEqual("98765432109876543\n", handle.read())

    def test_overwrite_then_two_matching_entries_replaces_the_file(self):
        with tempfile.TemporaryDirectory() as directory:
            status, output, account_file, _ = self.run_set_account(
                directory,
                [(b"Type OVERWRITE to replace it: ", b"OVERWRITE"), *self.written_prompts(self.account)],
                existing="98765432109876543",
                existing_mode=0o644,
            )
            self.assertEqual(0, status, output)
            with open(account_file, encoding="utf-8") as handle:
                self.assertEqual(f"{self.account}\n", handle.read())
            self.assertEqual(0o600, stat.S_IMODE(os.stat(account_file).st_mode))
            self.assertNotIn(self.account, output)
            self.assertNotIn("98765432109876543", output)

    def test_a_symbolic_link_is_refused_and_its_target_is_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "not-the-account-file")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("synthetic\n")
            status, output, account_file, _ = self.run_set_account(directory, [], symlink_to=target)
            self.assertEqual(2, status, output)
            self.assertIn("symbolic link", output)
            self.assertTrue(os.path.islink(account_file))
            with open(target, encoding="utf-8") as handle:
                self.assertEqual("synthetic\n", handle.read())

    def test_set_key_and_set_account_together_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            config_dir = os.path.join(directory, "config")
            os.makedirs(config_dir)
            env = os.environ.copy()
            env["BCS_CONFIG_DIR"] = config_dir
            script = os.path.join(HELPER, "tools", "bcs_auth.sh")
            result = subprocess.run(
                ["bash", script, "--set-key", "--set-account"], capture_output=True, env=env, text=True
            )
            output = result.stdout + result.stderr
            self.assertEqual(2, result.returncode, output)
            self.assertIn("one at a time", output)
            self.assertEqual([], os.listdir(config_dir))

    def test_without_a_terminal_set_account_refuses_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            config_dir = os.path.join(directory, "config")
            os.makedirs(config_dir)
            env = os.environ.copy()
            env["BCS_CONFIG_DIR"] = config_dir
            script = os.path.join(HELPER, "tools", "bcs_auth.sh")
            result = subprocess.run(
                ["bash", script, "--set-account"],
                capture_output=True,
                env=env,
                text=True,
                stdin=subprocess.DEVNULL,
            )
            output = result.stdout + result.stderr
            self.assertEqual(2, result.returncode, output)
            self.assertIn("interactive terminal", output)
            self.assertEqual([], os.listdir(config_dir))

    def test_with_account_without_the_file_stops_before_anything_opens(self):
        with tempfile.TemporaryDirectory() as directory:
            state_home = os.path.join(directory, "state-home")
            status, output, _, config_dir = self.run_tool(
                directory,
                "--with-account",
                [],
                existing="c0ffee12",
                extra_env={"XDG_STATE_HOME": state_home},
            )
            self.assertEqual(2, status, output)
            self.assertIn("needs an account ID", output)
            self.assertIn("--set-account", output)
            # Nothing was opened and nothing was written: no account file, no state directory.
            self.assertFalse(os.path.exists(os.path.join(config_dir, "account.txt")))
            self.assertFalse(os.path.exists(os.path.join(state_home, "aether-bcs")))
            self.assertNotIn("about to authenticate", output)

    def test_with_account_and_a_valid_file_stops_with_exit_3_and_still_opens_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            state_home = os.path.join(directory, "state-home")
            config_dir = os.path.join(directory, "config")
            os.makedirs(config_dir)
            account_file = os.path.join(config_dir, "account.txt")
            with open(account_file, "w", encoding="utf-8") as handle:
                handle.write(self.account + "\n")
            os.chmod(account_file, 0o600)
            status, output, key_file, _ = self.run_tool(
                directory,
                "--with-account",
                [],
                existing="c0ffee12",
                extra_env={"XDG_STATE_HOME": state_home},
            )
            self.assertEqual(3, status, output)
            self.assertIn("cannot send the account frame yet", output)
            self.assertIn("0x7C/0x7D/0x7E", output)
            self.assertNotIn(self.account, output)
            self.assertNotIn("about to authenticate", output, "the gate must run before the prompt")
            self.assertFalse(os.path.exists(os.path.join(state_home, "aether-bcs")))
            with open(account_file, encoding="utf-8") as handle:
                self.assertEqual(f"{self.account}\n", handle.read())
            with open(key_file, encoding="utf-8") as handle:
                self.assertEqual("c0ffee12\n", handle.read())


class BcsAuthIdentityTest(unittest.TestCase):
    """Phase 3G (D3/D4): the self auth id is 32 uppercase hex characters from node:crypto.

    The identity is written by the driver, not by a library, so these tests drive the driver the way
    a live run does — through a stub sidecar on PATH and a real pseudo-terminal for the gate — and
    read the file back. No radio, no Bluetooth, no real key: the "key" is synthetic and the sidecar
    is a stub that never opens a socket. The run itself ends in a timeout, which is the point: the
    identity exists before any handshake byte is answered.
    """

    def run_live(self, directory, extra_env=None, timeout=60):
        bin_dir = os.path.join(directory, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        started = os.path.join(directory, "sidecar-started")
        stopped = os.path.join(directory, "sidecar-stopped")
        write_sidecar_stub(bin_dir, started, stopped)
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required for the offline identity tests")
        key_file = os.path.join(directory, "synthetic-key")
        with open(key_file, "w", encoding="utf-8") as handle:
            handle.write("a1b2c3d4\n")
        os.chmod(key_file, 0o600)
        state_dir = os.path.join(directory, "state")
        env = os.environ.copy()
        env.update(
            {
                "PATH": bin_dir + os.pathsep + env["PATH"],
                "HOME": directory,
                "XDG_CONFIG_HOME": os.path.join(directory, "config-home"),
                "BCS_AUTH_KEY_FILE": key_file,
                "BCS_STATE_DIR": state_dir,
                # The stub answers the handshake with silence, so the run is capped small on purpose.
                "BCS_DEADLINE_MS": "3000",
            }
        )
        env.update(extra_env or {})
        driver = os.path.join(HELPER, "tools", "bcs_auth.mjs")
        sent = set()

        def respond(master, text):
            if "type AUTHENTICATE to continue:" in text and "confirmation" not in sent:
                os.write(master, b"AUTHENTICATE\n")
                sent.add("confirmation")

        exited, status, output = run_on_pty([node, driver], env, respond, timeout=timeout)
        self.assertTrue(exited, output.decode("utf-8", "replace"))
        return os.waitstatus_to_exitcode(status), output.decode("utf-8", "replace"), state_dir

    def read_identity(self, state_dir):
        path = os.path.join(state_dir, "identity.json")
        with open(path, encoding="utf-8") as handle:
            return path, json.load(handle)

    def test_a_live_run_writes_an_uppercase_identity_and_never_prints_it(self):
        with tempfile.TemporaryDirectory() as directory:
            status, output, state_dir = self.run_live(directory)
            path, parsed = self.read_identity(state_dir)
            self.assertRegex(parsed["id"], r"^[0-9A-F]{32}$", output)
            self.assertEqual(0o600, stat.S_IMODE(os.stat(path).st_mode))
            # Nothing about the id is printed: not the value, not its case.
            self.assertNotIn(parsed["id"], output)

    def test_a_stored_lowercase_identity_is_rewritten_in_uppercase_in_place(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = os.path.join(directory, "state")
            os.makedirs(state_dir, mode=0o700)
            lower = "0123456789abcdef0123456789abcdef"
            path = os.path.join(state_dir, "identity.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"id": lower, "createdAt": "2026-01-01T00:00:00.000Z"}, handle)
            os.chmod(path, 0o600)
            _status, output, _state_dir = self.run_live(directory)
            with open(path, encoding="utf-8") as handle:
                parsed = json.load(handle)
            # The same 32 characters, in the case upstream uses, and the same creation time: this is a
            # migration, not a new identity.
            self.assertEqual(lower.upper(), parsed["id"])
            self.assertEqual("2026-01-01T00:00:00.000Z", parsed["createdAt"])
            self.assertIn("rewritten in the uppercase form", output)
            self.assertNotIn(lower, output)

    def test_an_uppercase_identity_is_left_exactly_as_it_is(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = os.path.join(directory, "state")
            os.makedirs(state_dir, mode=0o700)
            upper = "0123456789ABCDEF0123456789ABCDEF"
            path = os.path.join(state_dir, "identity.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"id": upper, "createdAt": "2026-01-01T00:00:00.000Z"}, handle)
            os.chmod(path, 0o600)
            _status, output, _state_dir = self.run_live(directory)
            with open(path, encoding="utf-8") as handle:
                parsed = json.load(handle)
            self.assertEqual(upper, parsed["id"])
            self.assertNotIn("rewritten in the uppercase form", output)


class BcsAuthDriverLifecycleTest(unittest.TestCase):
    def test_a_typed_pin_that_never_arrives_stops_the_fake_sidecar_child(self):
        # --pin is the opt-in path: the wrapper says it prompted, so the driver requires a pin on
        # stdin. With the pipe closed and nothing typed, the run stops before the handshake starts,
        # and the child that was already spawned is stopped rather than left behind.
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required for the offline driver lifecycle test")
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = os.path.join(directory, "bin")
            os.makedirs(bin_dir)
            key_file = os.path.join(directory, "synthetic-key")
            with open(key_file, "w", encoding="utf-8") as handle:
                handle.write("a1b2c3d4\n")
            os.chmod(key_file, 0o600)
            started_marker = os.path.join(directory, "sidecar-started")
            stopped_marker = os.path.join(directory, "sidecar-stopped")
            write_sidecar_stub(bin_dir, started_marker, stopped_marker)
            driver = os.path.join(HELPER, "tools", "bcs_auth.mjs")
            env = os.environ.copy()
            env.update(
                {
                    "PATH": bin_dir + os.pathsep + env["PATH"],
                    "BCS_AUTH_KEY_FILE": key_file,
                    "BCS_AUTH_MODE": "auth-then-bind",
                    "BCS_PIN_PROMPT": "1",
                    "BCS_STATE_DIR": os.path.join(directory, "state"),
                }
            )
            pid, master = pty.fork()
            if pid == 0:
                os.execve(node, [node, driver], env)
            output = bytearray()
            sent_confirmation = False
            sent_eof = False
            exited = False
            # 30 s so a machine under load fails a hang, not Node's cold start.
            deadline = time.monotonic() + 30
            try:
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([master], [], [], 0.1)
                    if ready:
                        try:
                            output.extend(os.read(master, 4096))
                        except OSError:
                            pass
                    text = output.decode("utf-8", "replace")
                    if not sent_confirmation and "type AUTHENTICATE to continue:" in text:
                        os.write(master, b"AUTHENTICATE\n")
                        sent_confirmation = True
                    if sent_confirmation and not sent_eof and os.path.exists(started_marker):
                        os.write(master, b"\x04")
                        sent_eof = True
                    waited, status = os.waitpid(pid, os.WNOHANG)
                    if waited == pid:
                        exited = True
                        break
                self.assertTrue(exited, output.decode("utf-8", "replace"))
                self.assertTrue(sent_eof, output.decode("utf-8", "replace"))
                self.assertIn(b"no 4-12 digit pin code", output)
                self.assertEqual(2, os.waitstatus_to_exitcode(status))
                self.assertTrue(os.path.exists(started_marker), "the fake sidecar should have started")
                self.assertTrue(
                    os.path.exists(stopped_marker), "the missing-pin return must stop the sidecar"
                )
                self.assertNotIn(b"a1b2c3d4", output)
            finally:
                if not exited:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.waitpid(pid, 0)
                if os.path.exists(started_marker) and not os.path.exists(stopped_marker):
                    try:
                        with open(started_marker, encoding="utf-8") as handle:
                            sidecar_pid = int(handle.read())
                        os.kill(sidecar_pid, signal.SIGTERM)
                    except (OSError, ValueError, ProcessLookupError):
                        pass
                os.close(master)

    def test_an_explicit_key_path_still_requires_the_key_before_starting_the_sidecar(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required for the offline driver lifecycle test")
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = os.path.join(directory, "bin")
            os.makedirs(bin_dir)
            started = os.path.join(directory, "sidecar-started")
            stopped = os.path.join(directory, "sidecar-stopped")
            write_sidecar_stub(bin_dir, started, stopped)
            env = os.environ.copy()
            env.update({
                "PATH": bin_dir + os.pathsep + env["PATH"],
                "HOME": directory,
                "BCS_AUTH_MODE": "auth-then-bind",
                "BCS_AUTH_KEY_EXPLICIT": "1",
                "BCS_AUTH_KEY_FILE": os.path.join(directory, "absent-key"),
                "BCS_STATE_DIR": os.path.join(directory, "state"),
            })
            sent = set()

            def respond(master, text):
                if "type AUTHENTICATE to continue:" in text and "confirmation" not in sent:
                    os.write(master, b"AUTHENTICATE\n")
                    sent.add("confirmation")

            driver = os.path.join(HELPER, "tools", "bcs_auth.mjs")
            exited, status, output = run_on_pty([node, driver], env, respond, timeout=60)
            text = output.decode("utf-8", "replace")
            self.assertTrue(exited, text)
            self.assertEqual(2, os.waitstatus_to_exitcode(status), text)
            self.assertIn("cannot read the auth key file", text)
            self.assertFalse(os.path.exists(started), "an explicit key failure must precede the sidecar")

    def test_the_default_auth_then_bind_run_asks_the_watch_and_never_prompts(self):
        """The default pin path: nothing is typed here, so the run must not wait for a pin.

        The stub sidecar answers the ping, the SDP resolve and the connect, then falls silent, so the
        run ends on its own deadline with exit 4 — which is what "the gate was passed and the handshake
        began" looks like from outside. The pin itself is the machine's business: it asks the watch
        (PinCode 0x01/0x2C) and decrypts the reply with the static digest secret. That contract is
        tested frame by frame in test/huaweiAuthMachine.test.ts; what is proved here is the wiring —
        no prompt, no stdin read, and the source named in the run's own report.
        """
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required for the offline driver lifecycle test")
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = os.path.join(directory, "bin")
            os.makedirs(bin_dir)
            started_marker = os.path.join(directory, "sidecar-started")
            stopped_marker = os.path.join(directory, "sidecar-stopped")
            write_sidecar_stub(bin_dir, started_marker, stopped_marker)
            key_file = os.path.join(directory, "deliberately-absent-key")
            state_dir = os.path.join(directory, "state")
            env = os.environ.copy()
            env.update(
                {
                    "PATH": bin_dir + os.pathsep + env["PATH"],
                    "BCS_AUTH_KEY_FILE": key_file,
                    "BCS_AUTH_MODE": "auth-then-bind",
                    "BCS_STATE_DIR": state_dir,
                    # The stub answers the handshake with silence, so the run is capped small on purpose.
                    "BCS_DEADLINE_MS": "3000",
                }
            )
            # BCS_PIN_PROMPT is deliberately absent: this is the default run, and the default run has
            # nothing to type. Only the gate's word goes into the terminal.
            typed = set()

            def respond(master, text):
                if "type AUTHENTICATE to continue:" in text and "confirmation" not in typed:
                    os.write(master, b"AUTHENTICATE\n")
                    typed.add("confirmation")

            driver = os.path.join(HELPER, "tools", "bcs_auth.mjs")
            exited, status, output = run_on_pty([node, driver], env, respond, timeout=60)
            text = output.decode("utf-8", "replace")
            self.assertTrue(exited, text)
            self.assertIn("confirmation", typed, text)
            # The gate was passed and the handshake began: the watch's silence is what ended the run.
            self.assertIn("link open after", text)
            self.assertIn("starting the auth-then-bind operation", text)
            self.assertEqual(4, os.waitstatus_to_exitcode(status), text)
            # Where the pin comes from, in the driver's own words: the watch, never this terminal.
            self.assertIn("pin code: asked of the watch (PinCode 0x01/0x2C), decrypted in memory", text)
            self.assertNotIn("no 4-12 digit pin code", text)
            self.assertNotIn("(hidden, not stored)", text)
            self.assertNotIn("a1b2c3d4", text)
            self.assertFalse(os.path.exists(key_file), "default auth-then-bind must not need a key file")
            self.assertTrue(os.path.exists(started_marker), "the fake sidecar should have started")
            self.assertTrue(os.path.exists(stopped_marker), "the run must stop the sidecar")
            # The report says the same, and no pin appears in it because none was ever in hand.
            reports = [name for name in os.listdir(state_dir) if name.startswith("auth-report-")]
            self.assertEqual(1, len(reports), reports)
            with open(os.path.join(state_dir, reports[0]), encoding="utf-8") as handle:
                body = handle.read()
            self.assertIn("pin code: asked of the watch", body)

    def test_a_17_digit_account_value_is_refused_before_the_sidecar_is_spawned(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required for the offline driver lifecycle test")
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = os.path.join(directory, "bin")
            os.makedirs(bin_dir)
            account = "12345678901234567"
            key_file = os.path.join(directory, "synthetic-key")
            with open(key_file, "w", encoding="utf-8") as handle:
                handle.write(account + "\n")
            os.chmod(key_file, 0o600)
            started_marker = os.path.join(directory, "sidecar-started")
            stopped_marker = os.path.join(directory, "sidecar-stopped")
            write_sidecar_stub(bin_dir, started_marker, stopped_marker)
            driver = os.path.join(HELPER, "tools", "bcs_auth.mjs")
            env = os.environ.copy()
            env.update(
                {
                    "PATH": bin_dir + os.pathsep + env["PATH"],
                    "BCS_AUTH_KEY_FILE": key_file,
                    "BCS_STATE_DIR": os.path.join(directory, "state"),
                }
            )
            sent = set()

            def respond(master, text):
                if "confirmation" not in sent and "type AUTHENTICATE to continue:" in text:
                    os.write(master, b"AUTHENTICATE\n")
                    sent.add("confirmation")

            exited, status, output = run_on_pty([node, driver], env, respond)
            text = output.decode("utf-8", "replace")
            self.assertTrue(exited, text)
            self.assertIn("confirmation", sent, text)
            self.assertEqual(2, os.waitstatus_to_exitcode(status), text)
            self.assertIn("hexadecimal characters", text)
            self.assertIn("account ID", text)
            self.assertNotIn(account, text)
            self.assertFalse(
                os.path.exists(started_marker),
                "the key format must be refused before the sidecar is spawned",
            )

    # --- --with-account: the account gate, which must happen before anything is opened -------------

    def run_driver_with_account(self, directory, account_text, **extra_env):
        """Run the driver on a pty with BCS_WITH_ACCOUNT=1 and a fake python3, and report what happened.

        Returns (exit code, output text, sidecar marker path). The fake python3 writes a marker if the
        driver ever spawns it, so "refused before the radio" is a fact and not a promise.
        """
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required for the offline driver lifecycle test")
        bin_dir = os.path.join(directory, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        key_file = os.path.join(directory, "synthetic-key")
        with open(key_file, "w", encoding="utf-8") as handle:
            handle.write("a1b2c3d4\n")
        os.chmod(key_file, 0o600)
        account_file = os.path.join(directory, "synthetic-account")
        if account_text is not None:
            with open(account_file, "w", encoding="utf-8") as handle:
                handle.write(account_text)
            os.chmod(account_file, 0o600)
        started_marker = os.path.join(directory, "sidecar-started")
        stopped_marker = os.path.join(directory, "sidecar-stopped")
        write_sidecar_stub(bin_dir, started_marker, stopped_marker)
        driver = os.path.join(HELPER, "tools", "bcs_auth.mjs")
        env = os.environ.copy()
        env.update(
            {
                "PATH": bin_dir + os.pathsep + env["PATH"],
                "BCS_AUTH_KEY_FILE": key_file,
                "BCS_AUTH_ACCOUNT_FILE": account_file,
                "BCS_WITH_ACCOUNT": "1",
                "BCS_STATE_DIR": os.path.join(directory, "state"),
            }
        )
        env.update(extra_env)
        sent = set()

        def respond(master, text):
            if "confirmation" not in sent and "type AUTHENTICATE to continue:" in text:
                os.write(master, b"AUTHENTICATE\n")
                sent.add("confirmation")

        exited, status, output = run_on_pty([node, driver], env, respond)
        text = output.decode("utf-8", "replace")
        self.assertTrue(exited, text)
        self.assertIn("confirmation", sent, text)
        return os.waitstatus_to_exitcode(status), text, started_marker

    def test_a_missing_account_file_is_refused_before_the_sidecar_is_spawned(self):
        with tempfile.TemporaryDirectory() as directory:
            status, text, started_marker = self.run_driver_with_account(directory, None)
            self.assertEqual(2, status, text)
            self.assertIn("cannot read the account ID file", text)
            self.assertIn("--set-account", text)
            self.assertFalse(os.path.exists(started_marker), "no sidecar may be spawned without the account")

    def test_a_malformed_account_file_is_refused_before_the_sidecar_is_spawned(self):
        for value in ("1234567890123456", "1234567890123456x", "12345678901234567890"):
            with self.subTest(value=value):
                with tempfile.TemporaryDirectory() as directory:
                    status, text, started_marker = self.run_driver_with_account(directory, value + "\n")
                    self.assertEqual(2, status, text)
                    self.assertIn("--set-account", text)
                    self.assertNotIn(value, text)
                    self.assertFalse(os.path.exists(started_marker))

    def test_a_valid_account_stops_with_the_cipher_refusal_and_never_shows_the_value(self):
        account = "12345678901234567"
        with tempfile.TemporaryDirectory() as directory:
            status, text, started_marker = self.run_driver_with_account(directory, account + "\n")
            # Exit 3: blocked, with a typed code, before a single frame exists.
            self.assertEqual(3, status, text)
            self.assertIn("account-needs-cipher", text)
            self.assertIn("0x7C/0x7D/0x7E", text)
            self.assertNotIn(account, text)
            self.assertFalse(os.path.exists(started_marker), "the account step must not open the radio")
            # The driver writes one report per run, named by its UTC stamp: nothing is overwritten.
            reports = [name for name in os.listdir(os.path.join(directory, "state")) if name.startswith("auth-report-")]
            self.assertEqual(1, len(reports), reports)
            self.assertRegex(reports[0], r"^auth-report-\d{8}T\d{6}Z\.txt$")
            report = os.path.join(directory, "state", reports[0])
            self.assertTrue(os.path.exists(report))
            with open(report, encoding="utf-8") as handle:
                report_text = handle.read()
            self.assertNotIn(account, report_text)
            self.assertIn(f"account digits: {len(account)}", report_text)


class WatchAddressSaveOperationsTest(WatchAddressSaveTest):
    def args(self, command="save"):
        return watch_tool.parse_args(["--config", self.config, command])

    def quiet(self, line):  # noqa: ARG002 - mirrors print's signature
        pass

    def test_a_typed_address_is_saved_with_mode_0600_and_never_printed(self):
        lines = []
        code = watch_tool.cmd_save(self.args(), out=lines.append, ask=lambda prompt: ADDRESS)
        self.assertEqual(0, code)
        self.assertEqual(0o600, stat.S_IMODE(os.stat(self.config).st_mode))
        self.assertEqual(ADDRESS, bcs_bt.load_watch_address(self.config))
        text = "\n".join(lines)
        self.assertNotIn(ADDRESS, text)
        self.assertIn("XX:XX:XX:XX:EE:FF", text)

    def test_whitespace_around_the_typed_address_is_forgiven(self):
        code = watch_tool.cmd_save(self.args(), out=self.quiet, ask=lambda prompt: f"  {ADDRESS} \n")
        self.assertEqual(0, code)
        self.assertEqual(ADDRESS, bcs_bt.load_watch_address(self.config))

    def test_a_typo_saves_nothing(self):
        lines = []
        code = watch_tool.cmd_save(self.args(), out=lines.append, ask=lambda prompt: "AA:BB:CC:DD:EE")
        self.assertEqual(1, code)
        self.assertFalse(os.path.exists(self.config))
        self.assertIn("nothing was saved", "\n".join(lines))

    def test_an_interrupted_prompt_saves_nothing(self):
        def ask(prompt):  # noqa: ARG001
            raise KeyboardInterrupt

        self.assertEqual(1, watch_tool.cmd_save(self.args(), out=self.quiet, ask=ask))
        self.assertFalse(os.path.exists(self.config))

    def test_an_address_outside_the_bluez_cache_is_noted_but_still_saved(self):
        original = watch_tool._bluetoothctl_devices
        watch_tool._bluetoothctl_devices = lambda: ([("XX:XX:XX:XX:99:99", "Other")], None)
        self.addCleanup(setattr, watch_tool, "_bluetoothctl_devices", original)
        lines = []
        code = watch_tool.cmd_save(self.args(), out=lines.append, ask=lambda prompt: ADDRESS)
        self.assertEqual(0, code)
        self.assertIn("not in the BlueZ cache", "\n".join(lines))

    def test_show_reports_what_is_saved_without_printing_it(self):
        lines = []
        self.assertEqual(1, watch_tool.cmd_show(self.args("show"), out=lines.append))
        self.assertIn("not saved yet", "\n".join(lines))

        bcs_bt.save_watch_address(ADDRESS, self.config)
        lines = []
        self.assertEqual(0, watch_tool.cmd_show(self.args("show"), out=lines.append))
        text = "\n".join(lines)
        self.assertIn("XX:XX:XX:XX:EE:FF", text)
        self.assertIn("0o600", text)
        self.assertNotIn(ADDRESS, text)

    def test_no_subcommand_prints_help_and_stops_with_a_failure(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            watch_tool.main([])
        self.assertIn("usage", out.getvalue())


class BcsPairPromptTest(unittest.TestCase):
    def test_numeric_comparison_is_printed_before_its_prompt_and_never_misdescribed(self):
        with open(os.path.join(HELPER, "tools", "bcs_pair.sh"), encoding="utf-8") as handle:
            source = handle.read()
        pair_body = source[source.index("pair_watch() {"):source.index("# ----------------------------------------------------------------------------------------- probe")]
        self.assertLess(pair_body.index("Confirm passkey"), pair_body.index("confirm_passkey || return 1"))
        self.assertIn("BlueZ is asking whether passkey", source)
        self.assertIn("Do not type the six digits as the answer", source)
        self.assertNotIn("showing this same code", source)
        self.assertIn('session_send "no"\n      return 1 ;;', source)

    def test_the_pairing_helpers_offline_self_test_still_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            env = os.environ.copy()
            env.update({"HOME": directory, "XDG_STATE_HOME": os.path.join(directory, "state")})
            result = subprocess.run(
                ["bash", os.path.join(HELPER, "tools", "bcs_pair.sh"), "--self-test"],
                capture_output=True, text=True, env=env, timeout=60, check=False,
            )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("every check passed", result.stdout)


if __name__ == "__main__":
    unittest.main()