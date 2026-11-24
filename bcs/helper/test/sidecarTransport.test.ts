// BCS helper — Phase 1 (link only): tests for the sidecar client, driven by an in-memory pipe so
// no Python runs and no Bluetooth is involved. Fake pipe writes are not sent to any device.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// The pipe double answers with the exact lines sidecar/rfcomm_sidecar.py emits, so a change in
// the Python shape that the transport would misread shows up here.

import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { describe, test } from "node:test";
import { createLogger } from "../src/log.ts";
import { MASKED_ADDRESS } from "../src/mask.ts";
import { HUAWEI_SDP_UUID } from "../src/huawei/constants.ts";
import { createChildPipe } from "../src/sidecarProcess.ts";
import { MAX_LINE_BYTES } from "../src/sidecarProtocol.ts";
import { createSidecarTransport, type SidecarPipe } from "../src/sidecarTransport.ts";
import type { BcsClosedEvent, BcsDataCountEvent, BcsError } from "../src/types.ts";

class MemoryPipe implements SidecarPipe {
  sent: string[] = [];
  #lineHandlers: ((line: string) => void)[] = [];
  #endHandlers: ((reason: string) => void)[] = [];

  write(line: string): void {
    this.sent.push(line);
  }

  onLine(handler: (line: string) => void): void {
    this.#lineHandlers.push(handler);
  }

  onEnd(handler: (reason: string) => void): void {
    this.#endHandlers.push(handler);
  }

  /** The command the transport sent last, parsed. */
  lastCommand(): Record<string, unknown> {
    const line = this.sent.at(-1);
    assert.ok(line, "the transport sent no command");
    return JSON.parse(line) as Record<string, unknown>;
  }

  emit(message: Record<string, unknown>): void {
    this.emitRaw(JSON.stringify(message));
  }

  emitRaw(line: string): void {
    for (const handler of this.#lineHandlers) handler(line);
  }

  emitEnd(reason = "the sidecar exited with code 1"): void {
    for (const handler of this.#endHandlers) handler(reason);
  }

  /** Answer whatever command is outstanding, the way the Python side would. */
  answer(extra: Record<string, unknown> = {}): void {
    this.emit({ id: this.lastCommand().id, ok: true, ...extra });
  }
}

function harness(
  options: {
    requestTimeoutMs?: number;
    connectTimeoutMs?: number;
    sdpTimeoutMs?: number;
    btSecurity?: "none" | "low" | "medium" | "high";
    requireBond?: boolean;
  } = {},
) {
  const pipe = new MemoryPipe();
  const logs: string[] = [];
  const counts: BcsDataCountEvent[] = [];
  const errors: BcsError[] = [];
  const closed: BcsClosedEvent[] = [];
  const logger = createLogger({ prefix: "test", sink: (line) => logs.push(line) });
  const transport = createSidecarTransport({
    pipe,
    logger,
    onDataCount: (event) => counts.push(event),
    requestTimeoutMs: options.requestTimeoutMs ?? 50,
    connectTimeoutMs: options.connectTimeoutMs ?? 50,
    sdpTimeoutMs: options.sdpTimeoutMs,
    btSecurity: options.btSecurity,
    requireBond: options.requireBond,
  });
  transport.onError((err) => errors.push(err));
  transport.onClosed((info) => closed.push(info));
  return { pipe, logs, counts, errors, closed, transport };
}

describe("open", () => {
  test("ping returns the live sidecar capabilities", async () => {
    const { pipe, transport } = harness();
    const ping = transport.ping();
    assert.deepEqual(pipe.lastCommand(), { id: 1, cmd: "ping" });
    pipe.answer({ capabilities: ["connect", "write"] });
    assert.deepEqual(await ping, ["connect", "write"]);
  });

  test("the connect command carries the channel and never an address", async () => {
    const { pipe, transport, logs } = harness();
    const opening = transport.open({ channel: 15, timeoutMs: 4_000 });
    assert.deepEqual(pipe.lastCommand(), { id: 1, cmd: "connect", channel: 15, timeout_ms: 4_000 });
    pipe.answer({ address: "XX:XX:XX:XX:EE:FF", channel: 15 });
    await opening;
    assert.equal(transport.isOpen(), true);
    assert.match(logs.join("\n"), /connected to XX:XX:XX:XX:EE:FF on channel 15/);
  });

  test("the default connect timeout is used when the caller does not choose one", async () => {
    const { pipe, transport } = harness({ connectTimeoutMs: 2_500 });
    const opening = transport.open({ channel: 5 });
    assert.equal(pipe.lastCommand().timeout_ms, 2_500);
    pipe.answer();
    await opening;
  });

  test("a plain open sends exactly the command it sent before the link options existed", async () => {
    const { pipe, transport, logs } = harness();
    const opening = transport.open({ channel: 15, timeoutMs: 4_000 });
    assert.deepEqual(pipe.lastCommand(), { id: 1, cmd: "connect", channel: 15, timeout_ms: 4_000 });
    pipe.answer({ channel: 15 });
    await opening;
    assert.equal(logs.join("\n").includes("bt-security"), false);
  });

  test("a security level and the bond precondition travel as names", async () => {
    const { pipe, transport, logs } = harness();
    const opening = transport.open({ channel: 15, btSecurity: "medium", requireBond: true });
    assert.deepEqual(pipe.lastCommand(), {
      id: 1,
      cmd: "connect",
      channel: 15,
      timeout_ms: 50,
      bt_security: "medium",
      require_bond: true,
    });
    assert.match(logs.join("\n"), /link options: bt-security medium, require-bond on/);
    pipe.answer({ channel: 15 });
    await opening;
  });

  test("the transport's own defaults are used when open() does not name them", async () => {
    const { pipe, transport } = harness({ btSecurity: "high", requireBond: true });
    const opening = transport.open({ channel: 5 });
    assert.equal(pipe.lastCommand().bt_security, "high");
    assert.equal(pipe.lastCommand().require_bond, true);
    pipe.answer();
    await opening;
  });

  test("an unknown security level is refused before any command is sent", async () => {
    const { pipe, transport } = harness();
    await assert.rejects(transport.open({ channel: 5, btSecurity: "fips" as never }), (err: unknown) => {
      assert.equal((err as BcsError).code, "bad-config");
      assert.match((err as Error).message, /none, low, medium, high/);
      return true;
    });
    assert.equal(pipe.sent.length, 0);
  });

  test("a non-boolean requireBond is refused before any command is sent", async () => {
    const { pipe, transport } = harness();
    await assert.rejects(transport.open({ channel: 5, requireBond: "yes" as never }), (err: unknown) => {
      assert.equal((err as BcsError).code, "bad-config");
      return true;
    });
    assert.equal(pipe.sent.length, 0);
  });

  test("a refused secure link surfaces as security-refused, not as a permission problem", async () => {
    const { pipe, transport } = harness();
    const opening = transport.open({ channel: 5, btSecurity: "medium" });
    pipe.emit({ id: pipe.lastCommand().id, ok: false, code: "security-refused", errno: 13 });
    await assert.rejects(opening, (err: unknown) => {
      assert.equal((err as BcsError).code, "security-refused");
      assert.equal((err as BcsError).errno, 13);
      // The sentence is ours, written here: the sidecar's own line is never copied into it.
      assert.match((err as Error).message, /probably not bonded/);
      return true;
    });
  });

  test("a missing bond surfaces as not-bonded", async () => {
    const { pipe, transport } = harness();
    const opening = transport.open({ channel: 5, requireBond: true });
    pipe.emit({ id: pipe.lastCommand().id, ok: false, code: "not-bonded" });
    await assert.rejects(opening, (err: unknown) => {
      assert.equal((err as BcsError).code, "not-bonded");
      assert.match((err as Error).message, /not paired with this computer/);
      return true;
    });
  });

  test("the address in the log keeps its last two octets so two watches can be told apart", async () => {
    const { pipe, transport, logs } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.answer({ address: "XX:XX:XX:XX:42:7A", channel: 15 });
    await opening;
    assert.match(logs.join("\n"), /connected to XX:XX:XX:XX:42:7A on channel 15/);
  });

  test("if a sidecar version ever sent a full address, the logger still masks it", async () => {
    const { pipe, transport, logs } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.answer({ address: "AA:BB:CC:DD:EE:FF", channel: 15 });
    await opening;
    const text = logs.join("\n");
    assert.equal(text.includes("AA:BB:CC:DD:EE:FF"), false);
    assert.match(text, /XX:XX:XX:XX:EE:FF/);
  });

  test("payload-looking address text is replaced before it reaches logs", async () => {
    const { pipe, transport, logs } = harness();
    const privateHex = "aabbccddeeff00112233445566778899";
    const opening = transport.open({ channel: 15 });
    pipe.answer({ address: privateHex });
    await opening;
    assert.equal(logs.join("\n").includes(privateHex), false);
    assert.match(logs.join("\n"), /connected to XX:XX:XX:XX:XX:XX/);
  });

  test("a response with no address at all is logged without inventing one", async () => {
    const { pipe, transport, logs } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.answer({ channel: 15 });
    await opening;
    assert.match(logs.join("\n"), /connected to XX:XX:XX:XX:XX:XX on channel 15/);
  });

  test("a missing channel is refused without a single command being sent", async () => {
    const { pipe, transport } = harness();
    await assert.rejects(transport.open(), (err: unknown) => {
      assert.equal((err as BcsError).code, "missing-channel");
      assert.match((err as Error).message, /resolveChannel/);
      return true;
    });
    assert.deepEqual(pipe.sent, []);
  });

  test("a channel outside 1-30 is refused too, because SDP owns discovery", async () => {
    const { pipe, transport } = harness();
    for (const channel of [0, 31, -1, 4.5]) {
      await assert.rejects(transport.open({ channel }), (err: unknown) => {
        assert.equal((err as BcsError).code, "missing-channel");
        return true;
      });
    }
    assert.deepEqual(pipe.sent, []);
  });

  test("a refused connect becomes a coded error and the link stays closed", async () => {
    const { pipe, transport } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.emit({ id: 1, ok: false, code: "busy", error: "the watch is busy", errno: 16 });
    await assert.rejects(opening, (err: unknown) => {
      assert.equal((err as BcsError).code, "busy");
      assert.equal((err as BcsError).errno, 16);
      assert.equal((err as Error).message, "the link is busy");
      return true;
    });
    assert.equal(transport.isOpen(), false);
  });

  test("a code the transport does not know becomes unknown rather than a new code", async () => {
    const { pipe, transport } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.emit({ id: 1, ok: false, code: "haunted", error: "?" });
    await assert.rejects(opening, (err: unknown) => {
      assert.equal((err as BcsError).code, "unknown");
      return true;
    });
  });

  test("no saved address arrives from the sidecar as no-config", async () => {
    const { pipe, transport } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.emit({ id: 1, ok: false, code: "no-config", error: "no saved watch address" });
    await assert.rejects(opening, (err: unknown) => {
      assert.equal((err as BcsError).code, "no-config");
      return true;
    });
  });

  test("opening an open link is refused and sends nothing more", async () => {
    const { pipe, transport } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.answer({ address: "XX:XX:XX:XX:EE:FF" });
    await opening;
    await assert.rejects(transport.open({ channel: 15 }), (err: unknown) => {
      assert.equal((err as BcsError).code, "already-open");
      return true;
    });
    assert.equal(pipe.sent.length, 1);
  });
});

describe("resolveChannel: the channel comes from SDP, or there is no link", () => {
  test("the command names the Huawei service UUID and the saved channel", async () => {
    const { pipe, transport } = harness();
    const resolving = transport.resolveChannel({ expectChannel: 18 });
    assert.deepEqual(pipe.lastCommand(), {
      id: 1,
      cmd: "resolve_channel",
      uuid: HUAWEI_SDP_UUID,
      expect_channel: 18,
    });
    pipe.answer({ method: "sdptool", channel: 18, matched_uuid: true, matched_serial: false });
    const sdp = await resolving;
    assert.equal(sdp.channel, 18);
    assert.equal(sdp.method, "sdptool");
    assert.equal(sdp.matchedUuid, true);
    assert.equal(sdp.matchedSerial, false);
  });

  test("with no expected channel the command carries none", async () => {
    const { pipe, transport } = harness();
    const resolving = transport.resolveChannel();
    const command = pipe.lastCommand();
    assert.equal("expect_channel" in command, false);
    assert.equal(command.uuid, HUAWEI_SDP_UUID);
    pipe.answer({ method: "sdptool", channel: 7, matched_serial: true });
    assert.equal((await resolving).channel, 7);
  });

  test("the answer names the watch it asked about, masked", async () => {
    const { pipe, transport } = harness();
    const resolving = transport.resolveChannel();
    pipe.answer({ method: "sdptool", channel: 18, matched_uuid: true, address: "XX:XX:XX:XX:EE:FF" });
    assert.equal((await resolving).address, "XX:XX:XX:XX:EE:FF");
  });

  test("an address the sidecar forgot to mask is masked here, and rubbish becomes the placeholder", async () => {
    // A lookup prints this value and writes it to a report, so the transport never passes an unmasked
    // address through -- not even when a sidecar bug hands it one.
    for (const [address, expected] of [
      ["AA:BB:CC:DD:EE:FF", "XX:XX:XX:XX:EE:FF"],
      ["xx:xx:xx:xx:ee:ff", "XX:XX:XX:XX:EE:FF"],
      ["not an address", MASKED_ADDRESS],
      ["", MASKED_ADDRESS],
      [undefined, MASKED_ADDRESS],
    ] as [string | undefined, string][]) {
      const { pipe, transport } = harness();
      const resolving = transport.resolveChannel();
      pipe.answer({ method: "sdptool", channel: 18, matched_uuid: true, address });
      const sdp = await resolving;
      assert.equal(sdp.address, expected);
      assert.equal(sdp.address.includes("AA:BB"), false);
    }
  });

  test("the answer is logged with counts and evidence, and no address", async () => {
    const { pipe, transport, logs } = harness();
    const resolving = transport.resolveChannel({ expectChannel: 18 });
    pipe.answer({ method: "sdptool", channel: 18, matched_uuid: true });
    await resolving;
    const text = logs.join("\n");
    assert.match(text, /SDP resolved channel 18 through sdptool/);
    assert.match(text, /huawei uuid: yes/);
  });

  test("a detail line carrying an address is masked before it leaves the transport", async () => {
    const { pipe, transport } = harness();
    const resolving = transport.resolveChannel({ expectChannel: 18 });
    pipe.answer({ method: "sdptool", channel: 18, matched_uuid: true, detail: "record of AA:BB:CC:DD:EE:FF" });
    const sdp = await resolving;
    assert.equal(sdp.detail.includes("AA:BB:CC:DD:EE:FF"), false);
    assert.match(sdp.detail, /XX:XX:XX:XX:EE:FF/);
  });

  test("every SDP refusal keeps its own code, and nothing is ever connected", async () => {
    for (const code of ["sdp-unavailable", "sdp-no-channel", "sdp-unconfirmed", "sdp-disagreement"]) {
      const { pipe, transport } = harness();
      const resolving = transport.resolveChannel({ expectChannel: 18 });
      pipe.emit({ id: 1, ok: false, code, error: "the sidecar's own words" });
      await assert.rejects(resolving, (err: unknown) => {
        assert.equal((err as BcsError).code, code);
        // The message is this side's own sentence, never the sidecar's text.
        assert.equal((err as Error).message.includes("the sidecar's own words"), false);
        assert.ok((err as Error).message.length > 10);
        return true;
      });
      assert.equal(transport.isOpen(), false);
      // One command, and it was the resolve: no connect was ever asked for.
      assert.equal(pipe.sent.length, 1);
      assert.equal(pipe.lastCommand().cmd, "resolve_channel");
    }
  });

  test("an answer with no usable channel is a protocol error, not a silent zero", async () => {
    for (const channel of [undefined, 0, 31, 4.5, "18"]) {
      const { pipe, transport } = harness();
      const resolving = transport.resolveChannel();
      pipe.answer({ method: "sdptool", channel });
      await assert.rejects(resolving, (err: unknown) => {
        assert.equal((err as BcsError).code, "protocol");
        return true;
      });
    }
  });

  test("SDP gets its own timeout, so a slow sdptool answer is not a request timeout", async () => {
    // The request timeout is far shorter than the wait below: only sdpTimeoutMs can explain the
    // answer arriving instead of a rejection.
    const { pipe, transport } = harness({ requestTimeoutMs: 20, sdpTimeoutMs: 5_000 });
    const resolving = transport.resolveChannel({ expectChannel: 18 });
    await new Promise((resolve) => setTimeout(resolve, 150));
    pipe.answer({ method: "sdptool", channel: 18, matched_uuid: true });
    assert.equal((await resolving).channel, 18);
  });
});

describe("write and the aux channel", () => {
  test("write sends hex through the pipe and waits for its acknowledgment", async () => {
    const { pipe, transport } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.answer({ address: "XX:XX:XX:XX:EE:FF" });
    await opening;
    const writing = transport.write(new Uint8Array([0x5a, 0x01, 0xff]));
    assert.deepEqual(pipe.lastCommand(), { id: 2, cmd: "write", hex: "5a01ff" });
    pipe.answer({ bytes: 3, writes: 1 });
    await writing;
  });

  test("payload hex in a refused response is absent from thrown errors and logs", async () => {
    const made = harness();
    const opening = made.transport.open({ channel: 15 });
    made.pipe.answer({ address: "XX:XX:XX:XX:EE:FF" });
    await opening;
    const { pipe, transport, logs } = made;
    const privateHex = "deadbeef00112233445566778899aabb";
    const writing = transport.write(new Uint8Array([0x5a]));
    pipe.emit({ id: 2, ok: false, code: "write-refused", error: `refused ${privateHex}` });
    await assert.rejects(writing, (err: unknown) => {
      assert.equal((err as Error).message.includes(privateHex), false);
      return true;
    });
    assert.equal(logs.join("\n").includes(privateHex), false);
  });

  test("write on a closed transport is refused before a command is sent", async () => {
    const { pipe, transport } = harness();
    await assert.rejects(transport.write(new Uint8Array([1])), (err: unknown) => {
      assert.equal((err as BcsError).code, "not-open");
      return true;
    });
    assert.deepEqual(pipe.sent, []);
  });

  test("openAux needs the primary link first", async () => {
    const { pipe, transport } = harness();
    await assert.rejects(transport.openAux(16), (err: unknown) => {
      assert.equal((err as BcsError).code, "not-open");
      return true;
    });
    assert.deepEqual(pipe.sent, []);
  });

  test("openAux on an open link sends the command and surfaces the Phase 4 refusal", async () => {
    const { pipe, transport } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.answer({ address: "XX:XX:XX:XX:EE:FF" });
    await opening;
    const aux = transport.openAux(16);
    assert.deepEqual(pipe.lastCommand(), { id: 2, cmd: "open_aux", channel: 16 });
    pipe.emit({ id: 2, ok: false, code: "unsupported", error: "the aux channel is Phase 4" });
    await assert.rejects(aux, (err: unknown) => {
      assert.equal((err as BcsError).code, "unsupported");
      return true;
    });
    assert.equal(transport.isOpen(), true, "a refused aux channel must not drop the primary link");
  });
});

describe("events from the sidecar", () => {
  async function opened() {
    const made = harness();
    const opening = made.transport.open({ channel: 15 });
    made.pipe.answer({ address: "XX:XX:XX:XX:EE:FF" });
    await opening;
    return made;
  }

  test("bytes are counted for the logger and not handed to onData without hex", async () => {
    const { pipe, transport, logs, counts } = await opened();
    const delivered: { bytes: number; channel: number }[] = [];
    transport.onData((data, channel) => delivered.push({ bytes: data.length, channel }));
    pipe.emit({ event: "data", bytes: 37, at: "2026-10-22T10:00:00Z", channel: 15 });
    assert.deepEqual(counts, [{ bytes: 37, at: "2026-10-22T10:00:00Z", channel: 15 }]);
    assert.match(logs.join("\n"), /received 37 bytes on channel 15 at 2026-10-22T10:00:00Z/);
    assert.deepEqual(delivered, []);
  });

  test("the bytes reach onData from the pipe while only counts reach the logger", async () => {
    const { pipe, transport, logs, counts } = await opened();
    const delivered: { bytes: number; channel: number }[] = [];
    transport.onData((data, channel) => delivered.push({ bytes: data.length, channel }));
    const privateHex = "5a01c0ffee";
    pipe.emit({ event: "data", bytes: 5, at: "t", channel: 15, hex: privateHex });
    assert.deepEqual(delivered, [{ bytes: 5, channel: 15 }]);
    assert.equal(counts.at(-1)?.bytes, 5);
    assert.equal(logs.join("\n").includes(privateHex), false);
  });

  test("payload-looking timestamp text is sanitized before logger output", async () => {
    const { pipe, transport, logs, counts } = await opened();
    const privateHex = "aabbccddeeff00112233445566778899";
    pipe.emit({ event: "data", bytes: 16, at: privateHex, channel: 15 });
    assert.equal(counts.at(-1)?.at, "unknown time");
    assert.equal(logs.join("\n").includes(privateHex), false);
    const closing = transport.close();
    pipe.answer();
    await closing;
  });

  test("an onData error containing received bytes is sanitized before logs and error callbacks", async () => {
    const { pipe, transport, logs, errors } = await opened();
    const privateHex = "aabbccddeeff00112233445566778899";
    transport.onData(() => { throw new Error(privateHex); });
    pipe.emit({ event: "data", bytes: 16, at: "2026-10-22T10:00:00Z", channel: 15, hex: privateHex });
    assert.equal(errors.length, 1);
    assert.equal(errors[0].message.includes(privateHex), false);
    assert.equal(logs.join("\n").includes(privateHex), false);
  });

  test("stderr diagnostics and parsed protocol lines never log payload hex", () => {
    class FakeChild extends EventEmitter {
      stdout = new PassThrough();
      stderr = new PassThrough();
      stdin = new PassThrough();
      killed = false;
    }
    const child = new FakeChild();
    const logs: string[] = [];
    const logger = createLogger({ prefix: "process-test", sink: (line) => logs.push(line) });
    const pipe = createChildPipe(child as never, logger);
    const privateHex = "cafebabefeedface0011223344556677";
    let receivedLine = "";
    const endReasons: string[] = [];
    pipe.onLine((line) => { receivedLine = line; });
    pipe.onEnd((reason) => endReasons.push(reason));
    child.stdout.write(`${JSON.stringify({ event: "data", bytes: 16, at: "t", hex: privateHex })}\n`);
    child.stderr.write(`sidecar diagnostic ${privateHex}\n`);
    child.stdout.emit("error", new Error(privateHex));
    assert.match(receivedLine, new RegExp(privateHex));
    assert.equal(logs.join("\n").includes(privateHex), false);
    assert.match(logs.join("\n"), /sidecar emitted a diagnostic line/);
    assert.deepEqual(endReasons, ["the sidecar output pipe failed"]);
  });

  test("a child stdin error becomes a sidecar-ended notification, never an unhandled stream error", () => {
    class FakeChild extends EventEmitter {
      stdout = new PassThrough();
      stderr = new PassThrough();
      stdin = new PassThrough();
      killed = false;
    }
    const child = new FakeChild();
    const pipe = createChildPipe(child as never, createLogger({ sink: () => {} }));
    const endReasons: string[] = [];
    pipe.onEnd((reason) => endReasons.push(reason));
    child.stdin.emit("error", Object.assign(new Error("synthetic broken pipe"), { code: "EPIPE" }));
    assert.deepEqual(endReasons, ["the sidecar input pipe failed"]);
  });

  test("unusable hex is reported as a protocol error instead of vanishing", async () => {
    const { pipe, errors, logs } = await opened();
    pipe.emit({ event: "data", bytes: 1, at: "t", hex: "0g" });
    assert.equal(errors.length, 1);
    assert.equal(errors[0].code, "protocol");
    assert.match(logs.join("\n"), /sidecar reported a protocol error/);
  });

  test("a closed event ends the link and reaches onClosed and waitForClosed", async () => {
    const { pipe, transport, closed, logs } = await opened();
    const info = transport.waitForClosed();
    pipe.emit({ event: "closed", at: "2026-10-22T10:00:01Z", reason: "the watch closed the link" });
    assert.equal(transport.isOpen(), false);
    assert.equal(closed.length, 1);
    assert.equal(closed[0].reason, "the watch closed the link");
    assert.deepEqual(await info, { at: "2026-10-22T10:00:01Z", reason: "the watch closed the link" });
    assert.match(logs.join("\n"), /link ended: the watch closed the link/);
  });

  test("a closed event with no reason still says something", async () => {
    const { pipe, closed } = await opened();
    pipe.emit({ event: "closed" });
    assert.equal(closed[0].reason, "the sidecar closed the link");
  });

  test("payload-looking closed reasons are replaced before callbacks and logs", async () => {
    const { pipe, closed, logs } = await opened();
    const privateHex = "aabbccddeeff00112233445566778899";
    pipe.emit({ event: "closed", at: privateHex, reason: privateHex });
    assert.equal(closed[0].reason, "the sidecar closed the link");
    assert.equal(logs.join("\n").includes(privateHex), false);
  });

  test("an error event is surfaced without pretending the link died", async () => {
    const { pipe, transport, errors, logs } = await opened();
    pipe.emit({ event: "error", error: "the link was reset", code: "reset", errno: 104 });
    assert.equal(errors.length, 1);
    assert.equal(errors[0].code, "reset");
    assert.equal(errors[0].errno, 104);
    assert.equal(transport.isOpen(), true);
    assert.match(logs.join("\n"), /the link was reset/);
  });

  test("timeout is known and an invented event code becomes a structured unknown", async () => {
    const { pipe, errors, logs } = await opened();
    pipe.emit({ event: "error", error: "invented text", code: "not-a-code" });
    pipe.emit({ event: "error", error: "timed out", code: "timeout" });
    assert.deepEqual(errors.map((error) => error.code), ["unknown", "timeout"]);
    assert.equal(errors[0].message, "the sidecar reported an unknown error");
    assert.equal(errors[1].message, "the sidecar request timed out");
    assert.equal(logs.join("\n").includes("invented text"), false);
  });

  test("a malformed line is ignored rather than treated as fatal", async () => {
    const made = harness();
    const opening = made.transport.open({ channel: 15 });
    made.pipe.emitRaw("Traceback (most recent call last):");
    made.pipe.emitRaw("   ");
    made.pipe.answer({ address: "XX:XX:XX:XX:EE:FF" });
    await opening;
    assert.equal(made.transport.isOpen(), true);
    assert.match(made.logs.join("\n"), /ignoring an unparsable line/);
  });

  test("an over-long line is treated as a broken pipe", async () => {
    const { pipe, errors } = harness();
    pipe.emitRaw("x".repeat(MAX_LINE_BYTES + 1));
    assert.equal(errors.length, 1);
    assert.equal(errors[0].code, "protocol");
  });
});

describe("timeouts", () => {
  test("a command the sidecar never answers times out with the timeout code", async () => {
    const { pipe, transport } = harness({ requestTimeoutMs: 40 });
    const opening = transport.open({ channel: 15 });
    pipe.answer({ address: "XX:XX:XX:XX:EE:FF" });
    await opening;
    const aux = transport.openAux(16);
    await assert.rejects(aux, (err: unknown) => {
      assert.equal((err as BcsError).code, "timeout");
      assert.match((err as Error).message, /did not answer "open_aux" within 40 ms/);
      return true;
    });
  });

  test("a late answer after a timeout does not throw on a promise nobody holds", async () => {
    const { pipe, transport } = harness({ requestTimeoutMs: 20 });
    const opening = transport.open({ channel: 15 });
    pipe.answer({ address: "XX:XX:XX:XX:EE:FF" });
    await opening;
    const aux = transport.openAux(16);
    await assert.rejects(aux, (err: unknown) => {
      assert.equal((err as BcsError).code, "timeout");
      return true;
    });
    // The sidecar finally answers the command that already timed out. Nothing may blow up.
    pipe.emit({ id: 2, ok: true });
    assert.equal(transport.isOpen(), true);
  });
});

describe("close", () => {
  test("close sends one command and reports the caller as the reason", async () => {
    const { pipe, transport, logs, closed } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.answer({ address: "XX:XX:XX:XX:EE:FF" });
    await opening;
    const closing = transport.close();
    assert.deepEqual(pipe.lastCommand(), { id: 2, cmd: "close" });
    pipe.answer();
    await closing;
    assert.equal(transport.isOpen(), false);
    assert.deepEqual(closed.map((info) => info.reason), ["closed by the caller"]);
    assert.match(logs.join("\n"), /link ended: closed by the caller/);
  });

  test("close on a link that was never open sends nothing", async () => {
    const { pipe, transport, closed } = harness();
    await transport.close();
    assert.deepEqual(pipe.sent, []);
    assert.deepEqual(closed, []);
  });

  test("an unacknowledged close still ends the link, and says it was not acknowledged", async () => {
    const { pipe, transport, logs, closed } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.answer({ address: "XX:XX:XX:XX:EE:FF" });
    await opening;
    const closing = transport.close();
    pipe.emit({ id: 2, ok: false, code: "protocol", error: "the sidecar did not understand close" });
    await closing;
    assert.equal(transport.isOpen(), false);
    assert.equal(closed.length, 1);
    assert.match(logs.join("\n"), /close was not acknowledged/);
  });

  test("closing twice is harmless", async () => {
    const { pipe, transport } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.answer({ address: "XX:XX:XX:XX:EE:FF" });
    await opening;
    const closing = transport.close();
    pipe.answer();
    await closing;
    await transport.close();
    assert.equal(pipe.sent.length, 2);
  });
});

describe("the sidecar stopping", () => {
  test("a pending connect fails as sidecar-exited with the reason", async () => {
    const { pipe, transport } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.emitEnd("the sidecar exited with code 1");
    await assert.rejects(opening, (err: unknown) => {
      assert.equal((err as BcsError).code, "sidecar-exited");
      assert.match((err as Error).message, /the sidecar exited with code 1/);
      return true;
    });
    assert.equal(transport.isOpen(), false);
  });

  test("an open link ends when the sidecar stops, without a throw", async () => {
    const { pipe, transport, closed } = harness();
    const opening = transport.open({ channel: 15 });
    pipe.answer({ address: "XX:XX:XX:XX:EE:FF" });
    await opening;
    const info = transport.waitForClosed();
    pipe.emitEnd("the sidecar was killed (SIGKILL)");
    assert.equal(transport.isOpen(), false);
    assert.equal(closed[0].reason, "the sidecar was killed (SIGKILL)");
    assert.equal((await info).reason, "the sidecar was killed (SIGKILL)");
  });

  test("after the sidecar stops, further closes send nothing", async () => {
    const { pipe, transport } = harness();
    pipe.emitEnd();
    await transport.close();
    assert.deepEqual(pipe.sent, []);
  });
});