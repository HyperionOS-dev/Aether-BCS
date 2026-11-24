// BCS helper: tests for the in-memory transport. The fake never reaches Bluetooth hardware.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// The fake is where the BcsTransport contract is pinned, including the rule that writes require
// an explicit test opt-in. Everything can be tested with no Bluetooth hardware and no Python.

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { FakeTransport } from "../src/fakeTransport.ts";
import { bcsError, isBcsError, type BcsClosedEvent, type BcsError } from "../src/types.ts";

describe("FakeTransport", () => {
  test("open records the target and opens the transport", async () => {
    const fake = new FakeTransport();
    await fake.open({ channel: 15 });
    assert.equal(fake.state, "open");
    assert.deepEqual(fake.opens, [{ channel: 15 }]);
  });

  test("opening twice is refused rather than silently ignored", async () => {
    const fake = new FakeTransport();
    await fake.open({ channel: 15 });
    await assert.rejects(fake.open({ channel: 15 }), (err: unknown) => {
      assert.equal((err as BcsError).code, "already-open");
      return true;
    });
  });

  test("a failing open propagates the error and leaves the transport closed", async () => {
    const fake = new FakeTransport({ failOpenWith: bcsError("busy", "the watch is busy", 16) });
    await assert.rejects(fake.open({ channel: 15 }), (err: unknown) => {
      assert.equal((err as BcsError).code, "busy");
      assert.equal((err as BcsError).errno, 16);
      return true;
    });
    assert.equal(fake.state, "closed");
    assert.deepEqual(fake.opens, []);
  });

  test("write is refused by default, so a test can prove nothing was sent", async () => {
    const fake = new FakeTransport();
    await fake.open({ channel: 15 });
    await assert.rejects(fake.write(new Uint8Array([1, 2, 3])), (err: unknown) => {
      assert.equal((err as BcsError).code, "write-not-allowed");
      assert.match((err as Error).message, /link only/);
      return true;
    });
    assert.deepEqual(fake.writes, []);
  });

  test("write is only recorded when a test explicitly asks for it", async () => {
    const fake = new FakeTransport({ allowWrites: true });
    await fake.open({ channel: 15 });
    await fake.write(new Uint8Array([1, 2]), 16);
    assert.equal(fake.writes.length, 1);
    assert.deepEqual(fake.writes[0].channel, 16);
    assert.deepEqual(Array.from(fake.writes[0].data), [1, 2]);
  });

  test("write before open is not-open, which is a different mistake", async () => {
    const fake = new FakeTransport({ allowWrites: true });
    await assert.rejects(fake.write(new Uint8Array([1])), (err: unknown) => {
      assert.equal((err as BcsError).code, "not-open");
      return true;
    });
  });

  test("aux channels need the primary link first, as the real sidecar does", async () => {
    const fake = new FakeTransport();
    await assert.rejects(fake.openAux(16), (err: unknown) => {
      assert.equal((err as BcsError).code, "not-open");
      return true;
    });
    await fake.open({ channel: 15 });
    await fake.openAux(16);
    assert.deepEqual(fake.auxChannels, [16]);
  });

  test("bytes from the watch reach every onData handler with their channel", () => {
    const fake = new FakeTransport();
    const seen: { bytes: number; channel: number }[] = [];
    fake.onData((data, channel) => seen.push({ bytes: data.length, channel }));
    fake.emitData(new Uint8Array([1, 2, 3, 4]), 15);
    assert.deepEqual(seen, [{ bytes: 4, channel: 15 }]);
  });

  test("the watch dropping the link is reported once and flips the state", () => {
    const fake = new FakeTransport();
    const events: BcsClosedEvent[] = [];
    fake.onClosed((info) => events.push(info));
    void fake.open({ channel: 15 });
    fake.emitRemoteClose("the watch went to sleep");
    fake.emitRemoteClose("the watch went to sleep");
    assert.equal(fake.state, "closed");
    assert.equal(events.length, 1);
    assert.equal(events[0].reason, "the watch went to sleep");
    assert.match(events[0].at, /^\d{4}-\d{2}-\d{2}T/);
  });

  test("an error event reaches onError without closing the link", () => {
    const fake = new FakeTransport();
    const errors: BcsError[] = [];
    fake.onError((err) => errors.push(err));
    fake.emitError(bcsError("reset", "the link was reset", 104));
    assert.equal(errors.length, 1);
    assert.equal(errors[0].code, "reset");
    assert.ok(isBcsError(errors[0]));
  });

  test("close is idempotent and reports the caller as the reason", async () => {
    const fake = new FakeTransport();
    const reasons: string[] = [];
    fake.onClosed((info) => reasons.push(info.reason));
    await fake.open({ channel: 15 });
    await fake.close();
    await fake.close();
    assert.equal(fake.closeCount, 1);
    assert.deepEqual(reasons, ["closed by caller"]);
    assert.equal(fake.state, "closed");
  });
});

describe("types", () => {
  test("a bcsError carries a code, an errno and a real stack", () => {
    const err = bcsError("timeout", "no answer", null);
    assert.ok(err instanceof Error);
    assert.equal(err.code, "timeout");
    assert.equal(err.errno, null);
    assert.equal(isBcsError(err), true);
  });

  test("an ordinary error is not mistaken for a bcsError", () => {
    assert.equal(isBcsError(new Error("plain")), false);
    assert.equal(isBcsError("not an error"), false);
  });
});