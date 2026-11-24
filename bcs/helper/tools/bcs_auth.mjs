// BCS helper — Part 3B (trust/auth, LIVE): drive the HiChain auth flow against the watch, once.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in the helper directory for attribution and privacy rules (../NOTICE from here).
//
// WRITTEN, NEVER RUN. Nothing in the repository runs this file; it exists so the live step is
// reviewable before anyone presses the button. It is started by tools/bcs_auth.sh, which owns the
// human gate, the key file and the stream masker; this driver owns the sequence.
//
// What it does: resolves the RFCOMM channel through SDP, opens that channel the way Phase 1 does
// (through the Python sidecar), then hands every frame to `createAuthMachine` and writes back exactly
// the bytes the machine asks for. When the machine says "done", the handshake succeeded and the
// derived key exists in memory.
//
// Why SDP decides the channel: upstream never connects to a channel number. HuaweiBRSupport.java:51
// registers HuaweiConstants.UUID_SERVICE_HUAWEI_SDP (`82FF3820-8411-400C-B85A-55BDB32CF060`) and
// BtClassicIoThread.java:150-159 asks the stack for a socket to that service record, so the channel
// is whatever SDP says it is. A channel found by Phase 1's probe is a guess: this driver asks the
// sidecar to resolve the channel through SDP, refuses to start if SDP cannot be read, and refuses if
// SDP disagrees with the saved channel (BCS_CHANNEL). It never falls back to a probed channel, and
// the sidecar refuses to connect to any channel it did not resolve itself.
//
// What it never does:
//   * never prints, logs, echoes or stores the auth key, the derived key, a token, a MAC or a frame;
//     the only things it reports are a state name, a byte count, a duration and a typed error code,
//   * never takes a key on the command line: an optional key file path comes from BCS_AUTH_KEY_FILE;
//     default auth-then-bind reads no key file, while bind and an explicit key path do,
//   * never retries: one attempt, one link, one handshake, then out,
//   * never runs unless a live sidecar ping advertises write and SDP-resolve capability,
//   * writes and receives payload bytes only through the child pipe; logs contain counts only.
//
// Every run writes its own report: `$BCS_REPORT_FILE` when the wrapper sets it (a timestamped name
// under the state directory), otherwise `auth-report-<stamp>.txt` there. Nothing is overwritten, so a
// failed run cannot destroy the evidence of the run before it. The report always ends with the run
// journal: the stage reached, the stage trail, and how many bytes and frames crossed the link — which
// is what tells "the watch said nothing" apart from "the watch said something else".
//
// --sdp-only (BCS_SDP_ONLY=1) is the same resolve without the run: it asks the sidecar's live ping
// for "resolve", resolves the channel through SDP exactly as the handshake below does, prints the
// masked watch address, the service UUID, the channel, the method that named it and the evidence
// behind it, writes that to this run's report, and exits. It requires SDPLOOKUP on /dev/tty (not
// AUTHENTICATE), never reads the key, never writes the identity file, never opens an RFCOMM
// connection and never writes a frame.
//
// --with-account (BCS_WITH_ACCOUNT=1) asks for the account step that upstream sends after a finished
// bind (HuaweiSupportProvider.java:787). This driver reads the account file first, validates it, and
// then stops with exit 3 BEFORE the sidecar is spawned: the frame must be encrypted with the derived
// key (the 0x7C/0x7D/0x7E envelope), and that cipher is not part of this phase. Nothing about the
// account is printed, logged or reported — not even its digits; only its length ever appears.
//
// Exit codes: 0 = the handshake completed and the derived key was obtained (for --sdp-only: SDP
// named a channel and it matches the saved one); 1 = the flow stopped (the typed code is printed and
// in the report); 2 = it could not start (including: SDP refused to name the channel, --sdp-only was
// not confirmed, or BCS_PIN_PROMPT asked for a pin code and no 4-12 digit one arrived on stdin);
// 3 = blocked (the sidecar did not advertise allowlisted writes and SDP resolution); 4 = a step timed
// out; 5 = the link ended underneath the flow.
//
// Phase 3G link options, all three from the environment and all three off by default:
//   * BCS_BT_SECURITY=none|low|medium|high — ask the stack for that BT_SECURITY level before
//     connect(). `none` asks for nothing, which is what every earlier phase did; the option says
//     what we asked for, never what the stack granted.
//   * BCS_REQUIRE_BOND=1 — refuse to connect unless the sidecar can see `Bonded: yes` for the watch.
//     A precondition check only: it never pairs a watch, and an unverifiable state is a refusal.
//   * BCS_PHONE_MODEL=<1-32 printable ASCII> — the model string SecurityNegotiation advertises
//     (upstream sends Build.MODEL). Unset means the helper's own default, unchanged.
// None of the three is accepted with --sdp-only: a lookup opens no link and sends no frame.
//
// Where the pin code comes from (the change this file was edited for): upstream never asks the user.
// On the first connect it sends PinCode.Request (service 0x01, command 0x2C), decrypts the watch's
// reply with the *static* digest secret — never the auth key — and then digests the pin's uppercase
// hex text for the auth operation's step 1 (HuaweiSupportProvider.java:564-578,
// DeviceConfig.java:1419-1462, GetHiChainRequest.java:206-213; ours: authPackets.ts:181-206,
// authMachine.ts:414-424). That is now the default here: BCS_AUTH_MODE=auth-then-bind is enough,
// nothing is read from stdin, and the machine asks the watch for the pin code itself. BCS_PIN_PROMPT=1
// (the shell's --pin) opts in to the older behaviour — one line read from stdin — for a watch that
// does not answer that request; it is refused for any other operation and with --sdp-only. The pin,
// its digest and the psk are never printed, logged or written to the report.

import { spawnSidecar } from "../src/sidecarProcess.ts";
import { createHuaweiStream } from "../src/huawei/stream.ts";
import { createAuthMachine, validatePhoneModel } from "../src/huawei/authMachine.ts";
import { HUAWEI_SDP_UUID } from "../src/huawei/constants.ts";
import { accountFramePlan, encodeAccountFrame, tryParseAccountId } from "../src/huawei/account.ts";
import { hexToBytes, zeroBytes } from "../src/huawei/crypto.ts";
import { createRunJournal } from "../src/runJournal.ts";
import { createLogger } from "../src/log.ts";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, readSync, writeFileSync, writeSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { homedir } from "node:os";

/** Everything the driver reports goes through here: names, counts, durations — never bytes. */
function say(line) {
  process.stdout.write(`${line}\n`);
}

function fail(line) {
  process.stdout.write(`${line}\n`);
}

/**
 * The human gate. Nothing that reads the watch may start unattended, and a channel lookup reads it
 * just as a handshake does. The word differs on purpose — AUTHENTICATE for the handshake, SDPLOOKUP
 * for the lookup — so a lookup cannot be started by reflex at a prompt meant for authentication.
 */
function confirmOnTty() {
  let terminal;
  try {
    terminal = openSync("/dev/tty", "r+");
  } catch {
    say(`cannot start: an interactive terminal is required for ${CONFIRM_WORD} confirmation`);
    return false;
  }
  try {
    writeSync(terminal, `type ${CONFIRM_WORD} to continue: `);
    const answer = Buffer.alloc(64);
    let length = 0;
    const character = Buffer.alloc(1);
    while (length < answer.length) {
      const count = readSync(terminal, character, 0, 1, null);
      if (count === 0 || character[0] === 0x0a) break;
      if (character[0] !== 0x0d) answer[length++] = character[0];
    }
    if (answer.subarray(0, length).toString("utf8") !== CONFIRM_WORD) {
      say(
        SDP_ONLY
          ? "not confirmed: no sidecar was started and SDP was asked nothing"
          : "not confirmed: no key was read and no sidecar was started",
      );
      return false;
    }
    return true;
  } catch {
    say(`cannot start: the terminal could not read the ${CONFIRM_WORD} confirmation`);
    return false;
  } finally {
    closeSync(terminal);
  }
}

const STATE_DIR = process.env.BCS_STATE_DIR ?? join(process.env.XDG_STATE_HOME ?? join(homedir(), ".local", "state"), "aether-bcs");
const KEY_FILE = process.env.BCS_AUTH_KEY_FILE ?? join(homedir(), ".config", "aether-bcs", "auth-key.txt");
/** The account ID file. A different value from the key, in a different file (see account.ts). */
const ACCOUNT_FILE = process.env.BCS_AUTH_ACCOUNT_FILE ?? join(homedir(), ".config", "aether-bcs", "account.txt");
/** True when the run was asked for the account step upstream sends after a finished bind. */
const WITH_ACCOUNT = process.env.BCS_WITH_ACCOUNT === "1";
/**
 * True when the run only resolves the channel: no key, no identity, no link, no frame. The shell's
 * `--sdp-only` is the only thing that sets it.
 */
const SDP_ONLY = process.env.BCS_SDP_ONLY === "1";
/** The word a person has to type at the terminal. A lookup never asks for the handshake's word. */
const CONFIRM_WORD = SDP_ONLY ? "SDPLOOKUP" : "AUTHENTICATE";
const IDENTITY_FILE = join(STATE_DIR, "identity.json");
/** This run's stamp. The wrapper passes one so the log, the report and the terminal all agree. */
const RUN_STAMP =
  process.env.BCS_RUN_STAMP ?? new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
/** One report per run, never a rewrite of the last one. tools/bcs_auth.sh passes an explicit path. */
const REPORT_FILE = process.env.BCS_REPORT_FILE ?? join(STATE_DIR, `auth-report-${RUN_STAMP}.txt`);
const SIDECAR = join(dirname(fileURLToPath(import.meta.url)), "..", "sidecar", "rfcomm_sidecar.py");
/**
 * The saved channel: `--channel`, or BCS_CHANNEL, 18 by default. It is an *expectation*, not a
 * target — SDP has to name this channel, and refusing is better than connecting to something else.
 */
const CHANNEL = Number.parseInt(process.env.BCS_CHANNEL ?? "18", 10);
const SAVE_DERIVED = process.env.BCS_SAVE_DERIVED === "1";
const OVERALL_DEADLINE_MS = Number.parseInt(process.env.BCS_DEADLINE_MS ?? "120000", 10);
/**
 * Phase 3G link options. Both default to today's behaviour: `none` asks the stack for nothing and
 * require-bond is off, so a run that does not mention them builds exactly the link it built before.
 */
const BT_SECURITY = process.env.BCS_BT_SECURITY ?? "none";
const REQUIRE_BOND = process.env.BCS_REQUIRE_BOND === "1";
const BT_SECURITY_NAMES = ["none", "low", "medium", "high"];
/** The model SecurityNegotiation advertises. Empty means "use the helper's own default". */
const PHONE_MODEL = process.env.BCS_PHONE_MODEL ?? "";
/** Names only, never a value from the watch: this string goes into the log and the report. */
const LINK_OPTIONS = `bt-security ${BT_SECURITY}, require-bond ${REQUIRE_BOND ? "on" : "off"}`;
/** The operation this run performs. Only auth-then-bind ever involves a pin code. */
const AUTH_MODE = process.env.BCS_AUTH_MODE === "auth-then-bind" ? "auth-then-bind" : "bind";
/**
 * True when the wrapper asked for the pin at a hidden prompt (its --pin) instead of letting the watch
 * send it. Off by default: the watch's own reply to PinCode.Request (0x01/0x2C) is the normal path,
 * which is what upstream does, so a run that does not name BCS_PIN_PROMPT is not asked for anything.
 */
const PIN_PROMPT = process.env.BCS_PIN_PROMPT === "1";
/** Where this run's pin code came from. Names only — the value itself is never recorded anywhere. */
const PIN_SOURCE =
  AUTH_MODE === "auth-then-bind"
    ? (PIN_PROMPT
      ? "typed at a hidden prompt (--pin), delivered on stdin"
      : "asked of the watch (PinCode 0x01/0x2C), decrypted in memory")
    : "not used by this operation";
// Default auth-then-bind derives operation 1 from the watch PIN. An explicit --key still requests
// the file, but no default auth-then-bind run may fail just because auth-key.txt is absent.
const USES_STORED_KEY = AUTH_MODE === "bind" || process.env.BCS_AUTH_KEY_EXPLICIT === "1";

/** Read the upstream stored form: non-empty, even-length hexadecimal text decoded to bytes. */
function readKey() {
  let text;
  try {
    text = readFileSync(KEY_FILE, "utf8").trim();
  } catch {
    fail(`cannot read the auth key file at ${KEY_FILE}`);
    return null;
  }
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(text)) {
    fail("the auth key file must hold a Gadgetbridge auth key as hex: an even number of hexadecimal characters (32 for a 16-byte key)");
    fail("a 17-19 digit Huawei account ID is not the auth key; store the key with: bash tools/bcs_auth.sh --set-key");
    // Phase 3G (D5): --set-key --generate is not a way to obtain *the* auth key. On the HiChain path
    // the watch issues the long-term key, so a locally generated one cannot complete a bind; it is
    // only meaningful for HiChainLite/normal mode, which this helper refuses. Saying so here is the
    // cheapest place to stop a whole class of "the bind fails and I do not know why" runs.
    fail("a generated key cannot complete a HiChain bind: the watch issues the long-term key, and");
    fail("--set-key --generate exists only for the HiChainLite/normal mode this helper refuses.");
    return null;
  }
  const decoded = hexToBytes(text);
  if (!decoded.ok) {
    fail("the auth key file is not valid hexadecimal text");
    return null;
  }
  return decoded.value;
}

/**
 * The identity the watch binds to. Upstream sends a fake Android id (32 characters); the watch stores
 * it, so it has to stay the same across runs. It is not a secret, but it is ours, so it is generated
 * once and kept in the state directory rather than regenerated per run.
 *
 * Phase 3G (D3/D4): the id is 32 UPPERCASE hex characters drawn from `crypto.randomBytes(16)`, which
 * is what upstream does (`HuaweiSupportProvider.java:929` + the uppercase `GB.HEX_CHARS`), instead of
 * 32 lowercase characters from `Math.random`. A stored id in the old lowercase form is uppercased on
 * load and written back once: no bind has ever completed with the old value, so nothing can depend on
 * it. The id itself is never printed.
 */
const IDENTITY_PATTERN = /^[0-9a-fA-F]{32}$/;

function persistIdentity(id, createdAt) {
  mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(
    IDENTITY_FILE,
    `${JSON.stringify({ id, createdAt }, null, 2)}\n`,
    { mode: 0o600 },
  );
}

function readIdentity() {
  try {
    const parsed = JSON.parse(readFileSync(IDENTITY_FILE, "utf8"));
    if (typeof parsed.id === "string" && IDENTITY_PATTERN.test(parsed.id)) {
      const upper = parsed.id.toUpperCase();
      if (upper !== parsed.id) {
        // Migration, not a new identity: the same 32 characters in the case upstream uses.
        persistIdentity(upper, typeof parsed.createdAt === "string" ? parsed.createdAt : new Date().toISOString());
        say("identity: the stored id was lowercase and has been rewritten in the uppercase form a Gadgetbridge id uses");
      }
      return new Uint8Array(Buffer.from(upper, "utf8"));
    }
  } catch {
    // first run, or unreadable: fall through and make one
  }
  const id = randomBytes(16).toString("hex").toUpperCase();
  persistIdentity(id, new Date().toISOString());
  return new Uint8Array(Buffer.from(id, "utf8"));
}

/**
 * Choose the report path for this run. A timestamped name is unique on its own; if two runs land in
 * the same second, the second one takes a suffix instead of overwriting the first one's evidence.
 */
function reportPath() {
  if (!existsSync(REPORT_FILE)) return REPORT_FILE;
  return `${REPORT_FILE.replace(/\.txt$/, "")}-${process.pid}.txt`;
}

/**
 * Write this run's report and return its path so the caller can print it. `journal` supplies the
 * stage reached, the stage trail and the byte/frame counts. A report that cannot be written must not
 * change the outcome of the run.
 */
function report(lines, journal) {
  const path = reportPath();
  try {
    mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
    const body = [
      `run: ${new Date().toISOString()} (stamp ${RUN_STAMP})`,
      ...lines,
      ...(journal ? journal.lines() : []),
    ];
    writeFileSync(path, `${body.join("\n")}\n`, { mode: 0o600 });
    return path;
  } catch {
    return null;
  }
}

/** A logger that satisfies BcsLogger and writes nothing but counts, states and typed errors. */
export function quietLogger() {
  return createLogger({
    prefix: "bcs-auth",
    sink: (line) => process.stderr.write(`[${line}]\n`),
  });
}

/**
 * The frames the watch sent, in arrival order, reassembled by the Phase 2 stream. `next()` resolves
 * with a frame, with `{ error }` for a stream failure, or with null when the step timed out.
 */
function frameQueue(transport, journal) {
  const stream = createHuaweiStream();
  const queue = [];
  let notify = null;
  transport.onData((data) => {
    // Bytes first, then frames: a run that receives bytes which never reassemble into a frame has to
    // be reported as exactly that, not as silence.
    journal.data(data.length);
    const step = stream.push(data);
    for (const frame of step.frames) {
      journal.frame();
      queue.push(frame);
    }
    if (step.error) queue.push({ error: step.error });
    if (notify) notify();
  });
  return {
    next(timeoutMs) {
      return new Promise((resolve) => {
        let settled = false;
        const timer = setTimeout(() => {
          if (settled) return;
          settled = true;
          notify = null;
          resolve(null);
        }, timeoutMs);
        const check = () => {
          if (settled) return;
          if (queue.length === 0) {
            notify = check;
            return;
          }
          settled = true;
          clearTimeout(timer);
          notify = null;
          resolve(queue.shift());
        };
        check();
      });
    },
  };
}

/**
 * Run the handshake. One pass, no retry: write what the machine asked for, wait for exactly one
 * frame, hand it back. Nothing here inspects a frame's contents — the machine does that.
 */
async function runFlow(machine, transport, queue, isAborted, journal) {
  const lines = [];
  const abortResult = () => ({ ok: false, code: "deadline", lines: ["run aborted"] });
  if (isAborted()) return abortResult();
  let pending = machine.start();
  for (;;) {
    if (isAborted()) return abortResult();
    if (!pending.ok) {
      const { code, message, detail } = pending.error;
      journal.reached(`stopped: ${code}`);
      lines.push(`stopped: ${code}: ${message}${detail ? ` (${detail})` : ""}`);
      say(`stopped: ${code}`);
      say(`  ${message}${detail ? ` [${detail}]` : ""}`);
      return { ok: false, code, lines };
    }
    const output = pending.value;
    journal.reached(output.state);
    const bytes = output.out.reduce((total, frame) => total + frame.length, 0);
    lines.push(`${new Date().toISOString()} ${output.state} ${bytes} bytes in ${output.out.length} frame(s)`);
    say(`  ${output.state.padEnd(24)} ${String(bytes).padStart(4)} bytes`);
    for (const frame of output.out) {
      if (isAborted()) return abortResult();
      await transport.write(frame);
      journal.written(frame.length);
      if (isAborted()) return abortResult();
    }
    if (output.done) {
      journal.reached("done");
      lines.push("done: the handshake completed");
      return { ok: true, code: null, lines };
    }
    const next = await queue.next(machine.timeoutMs);
    if (isAborted()) return abortResult();
    if (next === null) {
      // Three different failures, said differently: silence, unframeable bytes, or the wrong frames.
      const silence = journal.silence(output.state, machine.timeoutMs);
      journal.reached(`timeout in ${output.state}`);
      lines.push(silence);
      say(silence);
      return { ok: false, code: "timeout", lines };
    }
    if (next.error) {
      journal.reached(`stream: ${next.error.code}`);
      lines.push(`stream: ${next.error.code}: ${next.error.message}`);
      say(`stream error: ${next.error.code}`);
      return { ok: false, code: next.error.code, lines };
    }
    pending = machine.onFrame(next);
  }
}

/**
 * The pin code, and only when the wrapper asked for one (BCS_PIN_PROMPT=1, the shell's --pin): one
 * line on stdin, so it is never in argv, never in the environment and never in a file. The default
 * path needs nothing here — the machine asks the watch for its pin code over the link and decrypts
 * the reply with the static digest secret.
 */
function readPin() {
  try {
    const text = readFileSync(0, "utf8").split("\n")[0].trim();
    return /^[0-9]{4,12}$/.test(text) ? new Uint8Array(Buffer.from(text, "utf8")) : null;
  } catch {
    return null;
  }
}

/**
 * The account ID, if this run needs one: digits only, 17 to 19 of them, trimmed like upstream does
 * (SendExtendedAccountRequest.java:49). Every failure names the shape of the problem and never the
 * value, so these lines are safe to print and to report.
 */
function readAccount() {
  let text;
  try {
    text = readFileSync(ACCOUNT_FILE, "utf8");
  } catch {
    fail(`cannot read the account ID file at ${ACCOUNT_FILE}`);
    fail("store the 17-19 digit Huawei account ID first: bash tools/bcs_auth.sh --set-account");
    return null;
  }
  const parsed = tryParseAccountId(text);
  if (!parsed.ok) {
    fail(`${parsed.error.code}: ${parsed.error.message}`);
    fail("store the account ID again with: bash tools/bcs_auth.sh --set-account");
    return null;
  }
  return parsed.value;
}

/**
 * The account gate for --with-account. Everything here happens before the sidecar is spawned, so a
 * run that cannot finish never opens a radio. Returns the exit code to leave with, or null to carry
 * on into the handshake.
 */
function accountGate() {
  const account = readAccount();
  if (account === null) return 2;
  const plan = accountFramePlan({ account });
  if (!plan.ok) {
    fail(`${plan.error.code}: ${plan.error.message}`);
    return 2;
  }
  const encoded = encodeAccountFrame(plan.value);
  if (encoded.ok) {
    // encodeAccountFrame() refuses every wire form until the transaction cipher exists. If that ever
    // changes, this gate has to be revisited deliberately — never silently send from here.
    fail("blocked: the account frame encoder no longer refuses the wire form; this gate needs review");
    return 3;
  }
  fail(`blocked: ${encoded.error.detail ?? encoded.error.code}`);
  fail(`  ${encoded.error.message}`);
  fail("  the sidecar was not started and no frame was sent. Run without --with-account to");
  fail("  authenticate on its own, or wait for the phase that adds the transaction cipher.");
  report([
    "blocked: the account frame needs the transaction cipher (0x7C/0x7D/0x7E)",
    `account digits: ${plan.value.digits}`,
    `checked at ${new Date().toISOString()}`,
  ]);
  return 3;
}

/**
 * `--sdp-only`: resolve the channel exactly as the handshake does, report the evidence and stop.
 *
 * What it deliberately does not do: read the key file, read or write the identity file, open an
 * RFCOMM connection, or write a frame. The sidecar is stopped before the report is written, so the
 * child is gone by the time this run's evidence lands on disk.
 *
 * It asks with no `expectChannel`: the point of a lookup is to see what SDP actually says. The
 * comparison with the saved channel is printed as its own line, and a disagreement is still a
 * refusal with `sdp-disagreement` — the same code and the same exit as a live run — because a live
 * run would not start either.
 */
async function sdpOnly(journal) {
  const spawned = spawnSidecar({ scriptPath: SIDECAR, emitHex: true, logger: quietLogger() });
  let capabilities;
  journal.reached("ping");
  try {
    capabilities = await spawned.transport.ping();
  } catch (error) {
    spawned.stop();
    say("cannot start: the sidecar did not answer its live capability ping");
    if (error?.code === "sidecar-exited") {
      say("  it exited before answering. The diagnostic lines above are its own, and they never");
      say("  carry the key, the account or the watch address.");
    }
    return 2;
  }
  // Only "resolve" is required here. A lookup never writes, so demanding "write" would refuse a
  // sidecar that can answer this question perfectly well.
  if (!capabilities.includes("resolve")) {
    spawned.stop();
    journal.reached("blocked");
    say(`blocked: the live ping from ${SIDECAR} did not advertise resolve`);
    say("  a sidecar that cannot resolve the channel through SDP cannot answer this question, and");
    say("  this helper never reports a channel found by probing. Update the helper.");
    const path = report(
      ["mode: sdp-only", "blocked: sidecar ping did not advertise resolve", `checked at ${new Date().toISOString()}`],
      journal,
    );
    if (path) say(`report: ${path}`);
    return 3;
  }

  journal.reached("sdp");
  say(`asking SDP which channel serves ${HUAWEI_SDP_UUID} (a probed channel is never used)...`);
  let sdp;
  try {
    sdp = await spawned.transport.resolveChannel({ uuid: HUAWEI_SDP_UUID });
  } catch (error) {
    const code = error?.code ?? "unknown";
    journal.reached(`sdp-refused: ${code}`);
    spawned.stop();
    say(`refused: ${code}: ${error?.message ?? ""}`);
    say("  no channel is proven. Nothing was connected: no RFCOMM socket was opened, no key was");
    say("  read, the run identity was not touched and no frame was sent.");
    const path = report(["mode: sdp-only", `refused: ${code}: ${error?.message ?? ""}`], journal);
    if (path) say(`report: ${path}`);
    return 2;
  }
  journal.reached("sdp-resolved");
  spawned.stop();

  // The masked address first: a lookup is evidence about one specific watch, and the sidecar already
  // masks the value before it leaves the process.
  const matches = sdp.channel === CHANNEL;
  const lines = [
    "mode: sdp-only (SDPLOOKUP; no RFCOMM connection, no key, no frame)",
    `watch: ${sdp.address} (masked)`,
    `service uuid: ${HUAWEI_SDP_UUID}`,
    `method: ${sdp.method}`,
    `channel: ${sdp.channel}`,
    `evidence: huawei uuid: ${sdp.matchedUuid ? "yes" : "no"}, serial record: ${sdp.matchedSerial ? "yes" : "no"}`,
    `saved channel: ${CHANNEL} (matches: ${matches ? "yes" : "no"})`,
  ];
  for (const line of lines) say(line);

  if (!matches) {
    journal.reached("sdp-disagreement");
    say(`refused: sdp-disagreement: SDP named channel ${sdp.channel}, but the saved channel is ${CHANNEL}`);
    say(`  a live run would refuse to start. Run it with --channel ${sdp.channel} once that is right.`);
    const path = report(
      lines.concat([`refused: sdp-disagreement (SDP named ${sdp.channel}, saved ${CHANNEL})`]),
      journal,
    );
    if (path) say(`report: ${path}`);
    return 2;
  }
  say("result: resolved — a live run would resolve this channel and connect to it");
  const path = report(lines.concat(["result: resolved (the channel a live run would use)"]), journal);
  if (path) say(`report: ${path}`);
  return 0;
}

async function main() {
  if (process.features?.typescript !== "strip" && process.features?.typescript !== true) {
    say(`cannot start: Node ${process.versions.node} does not strip TypeScript types; Node >= 22.6 is required`);
    return 2;
  }
  if (!Number.isInteger(CHANNEL) || CHANNEL < 1 || CHANNEL > 30) {
    say(`cannot start: channel must be 1-30, got ${process.env.BCS_CHANNEL ?? "(unset)"}`);
    return 2;
  }
  // Phase 3G options are checked before the terminal gate: a value that could never be used should
  // not ask anyone to type a confirmation word.
  if (!BT_SECURITY_NAMES.includes(BT_SECURITY)) {
    say(`cannot start: --bt-security takes one of ${BT_SECURITY_NAMES.join(", ")}, not "${BT_SECURITY}"`);
    return 2;
  }
  if (PHONE_MODEL !== "") {
    const model = validatePhoneModel(PHONE_MODEL);
    if (!model.ok) {
      say(`cannot start: ${model.error.code}: ${model.error.message}`);
      if (model.error.detail) say(`  ${model.error.detail}`);
      return 2;
    }
  }
  if (SDP_ONLY && (BT_SECURITY !== "none" || REQUIRE_BOND || PHONE_MODEL !== "" || PIN_PROMPT)) {
    // A lookup opens no link and sends no frame, so a link option, a wire value or a pin code has
    // nothing to apply to. Refusing says so; ignoring them would look like they had taken effect.
    say("cannot start: --bt-security, --require-bond, --phone-model and --pin belong to a live run");
    say("  --sdp-only opens no RFCOMM connection and sends no frame. Run them separately.");
    return 2;
  }
  if (PIN_PROMPT && AUTH_MODE !== "auth-then-bind") {
    // The bind operation keys its handshake from the stored key; only the auth operation takes a pin.
    say("cannot start: BCS_PIN_PROMPT asks for a pin code, which only --mode auth-then-bind uses");
    say(`  this run is ${AUTH_MODE}. Drop the pin, or ask for the auth-then-bind operation.`);
    return 2;
  }
  if (!confirmOnTty()) return 2;
  const journal = createRunJournal();
  journal.reached("confirmed");
  // A lookup run stops here, before the key is read and before the identity file is touched: it can
  // therefore never become a handshake, and it never opens a link.
  if (SDP_ONLY) return sdpOnly(journal);
  if (WITH_ACCOUNT) {
    const gate = accountGate();
    if (gate !== null) return gate;
  }
  const key = USES_STORED_KEY ? readKey() : new Uint8Array();
  if (!key) return 2;
  const spawned = spawnSidecar({ scriptPath: SIDECAR, emitHex: true, logger: quietLogger() });
  let capabilities;
  journal.reached("ping");
  try {
    capabilities = await spawned.transport.ping();
  } catch (error) {
    zeroBytes(key);
    spawned.stop();
    say("cannot start: the sidecar did not answer its live capability ping");
    if (error?.code === "sidecar-exited") {
      say("  it exited before answering. The diagnostic lines above are its own, and they never");
      say("  carry the key, the account or the watch address.");
    }
    return 2;
  }
  const missing = ["write", "resolve"].filter((capability) => !capabilities.includes(capability));
  if (missing.length) {
    zeroBytes(key);
    spawned.stop();
    journal.reached("blocked");
    say(`blocked: the live ping from ${SIDECAR} did not advertise ${missing.join(" and ")}`);
    if (missing.includes("resolve")) {
      say("  a sidecar that cannot resolve the channel through SDP cannot be used here: this helper");
      say("  never connects to a channel found by probing. Update the helper; never pass a channel.");
    }
    const path = report(
      [`blocked: sidecar ping did not advertise ${missing.join(" and ")}`, `checked at ${new Date().toISOString()}`],
      journal,
    );
    if (path) say(`report: ${path}`);
    return 3;
  }

  // The channel comes from SDP or this run does not happen. There is no fallback, no remembered
  // channel and no probed one: the sidecar refuses to connect to anything it did not resolve, and
  // this driver refuses to ask for anything else.
  journal.reached("sdp");
  say(`asking SDP which channel serves ${HUAWEI_SDP_UUID} (a probed channel is never used)…`);
  let sdp;
  try {
    sdp = await spawned.transport.resolveChannel({ uuid: HUAWEI_SDP_UUID, expectChannel: CHANNEL });
  } catch (error) {
    const code = error?.code ?? "unknown";
    journal.reached(`sdp-refused: ${code}`);
    say(`refused: ${code}: ${error?.message ?? ""}`);
    say("  nothing was connected: the link was never opened, and no probed channel was used.");
    const path = report([`refused: ${code}: ${error?.message ?? ""}`, `saved channel: ${CHANNEL}`], journal);
    if (path) say(`report: ${path}`);
    zeroBytes(key);
    spawned.stop();
    return 2;
  }
  say(
    `sdp: ${sdp.method} named channel ${sdp.channel} ` +
      `(huawei uuid: ${sdp.matchedUuid ? "yes" : "no"}, serial record: ${sdp.matchedSerial ? "yes" : "no"})`,
  );
  if (sdp.channel !== CHANNEL) {
    // The sidecar enforces this too; saying it here keeps the refusal in the driver's own words.
    journal.reached("sdp-disagreement");
    say(`refused: sdp-disagreement: SDP named channel ${sdp.channel}, but the saved channel is ${CHANNEL}`);
    say(`  nothing was connected. Check the record with sdptool, then run again with --channel ${sdp.channel}.`);
    const path = report([`refused: sdp-disagreement (SDP named ${sdp.channel}, saved ${CHANNEL})`], journal);
    if (path) say(`report: ${path}`);
    zeroBytes(key);
    spawned.stop();
    return 2;
  }
  journal.reached("sdp-resolved");

  const androidId = readIdentity();
  const mode = AUTH_MODE;
  // The pin code is the watch's to send: the machine asks for it (PinCode 0x01/0x2C) and decrypts the
  // reply with the static digest secret, exactly as upstream does. A manual pin is opt-in and only
  // ever read when the wrapper asked for it (--pin), so this is no longer a precondition of the mode.
  const pinCode = mode === "auth-then-bind" && PIN_PROMPT ? readPin() : null;
  if (mode === "auth-then-bind") {
    if (PIN_PROMPT && !pinCode) {
      say("cannot start: --pin was given, and no 4-12 digit pin code arrived on stdin");
      zeroBytes(key);
      spawned.stop();
      return 2;
    }
    say(`pin code: ${PIN_SOURCE}`);
  }

  const machine = createAuthMachine({
    key,
    androidId,
    mode,
    pinCode,
    ...(PHONE_MODEL !== "" ? { phoneModel: PHONE_MODEL } : {}),
  });
  const queue = frameQueue(spawned.transport, journal);
  const startedAt = Date.now();
  let aborted = false;
  let deadlineTimer;
  // Both link options, named: what the run asked the stack for, never what the watch answered.
  say(`link options: ${LINK_OPTIONS}${PHONE_MODEL !== "" ? `, phone-model ${PHONE_MODEL}` : ""}`);

  say(`opening channel ${sdp.channel} through the sidecar…`);
  try {
    await spawned.transport.open({
      channel: sdp.channel,
      btSecurity: BT_SECURITY,
      requireBond: REQUIRE_BOND,
    });
    journal.reached("link-open");
    say(`link open after ${Date.now() - startedAt}ms; starting the ${mode} operation`);
    const deadline = new Promise((resolve) => {
      deadlineTimer = setTimeout(() => {
        aborted = true;
        resolve({ ok: false, code: "deadline", lines: ["deadline reached"] });
      }, OVERALL_DEADLINE_MS);
    });
    const result = await Promise.race([runFlow(machine, spawned.transport, queue, () => aborted, journal), deadline]);
    clearTimeout(deadlineTimer);
    deadlineTimer = undefined;
    const derived = machine.finalKey ? Uint8Array.from(machine.finalKey) : null;
    if (result.ok && derived) {
      say(`done: handshake complete in ${Date.now() - startedAt}ms, derived key ${derived.length} bytes`);
      if (SAVE_DERIVED) {
        mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
        writeFileSync(join(STATE_DIR, "derived.key"), `${Buffer.from(derived).toString("hex")}\n`, { mode: 0o600 });
        say(`  saved to ${join(STATE_DIR, "derived.key")} (mode 0600): Phase 4 material, never printed`);
      } else {
        say("  not saved and not printed; pass BCS_SAVE_DERIVED=1 to keep it for Phase 4");
      }
      const path = report(
        result.lines.concat([
          `ok: derived ${derived.length} bytes, saved=${SAVE_DERIVED}`,
          `link options: ${LINK_OPTIONS}`,
          `pin code: ${PIN_SOURCE}`,
        ]),
        journal,
      );
      if (path) say(`report: ${path}`);
      zeroBytes(derived);
      return 0;
    }
    const path = report(
      result.lines.concat([`stopped: ${result.code}`, `link options: ${LINK_OPTIONS}`, `pin code: ${PIN_SOURCE}`]),
      journal,
    );
    if (path) say(`report: ${path}`);
    return result.code === "timeout" || result.code === "deadline" ? 4 : 1;
  } catch (error) {
    // A transport failure is a different animal from a silent watch, and the stage says which one:
    // the journal's last stage is the last thing that worked.
    say(`could not complete: ${error?.code ?? "unknown"}`);
    say(`  ${error?.message ?? ""}`);
    say(`  stage reached: ${journal.stage}; nothing was retried`);
    const path = report([`error: ${error?.code ?? "unknown"}: ${error?.message ?? ""}`], journal);
    if (path) say(`report: ${path}`);
    return 2;
  } finally {
    aborted = true;
    if (deadlineTimer) clearTimeout(deadlineTimer);
    machine.destroy();
    zeroBytes(key);
    if (pinCode) zeroBytes(pinCode);
    try {
      await spawned.transport.close();
    } catch {
      // A link that is already gone needs no closing.
    }
    spawned.stop();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((code) => process.exit(code)).catch((error) => {
    say(`unexpected failure: ${error?.message ?? error}`);
    process.exit(2);
  });
}