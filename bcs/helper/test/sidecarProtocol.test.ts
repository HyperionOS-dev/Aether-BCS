// BCS helper — Phase 1 (link only): tests for the pure half of the pipe. Phase 1 writes no
// bytes to the watch. Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// These are the lines the Python side really produces, including the broken ones: a parser that
// only ever sees well-formed input is a parser that has never been tested.

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  dataCountOf,
  encodeCommand,
  errorFromResponse,
  hexToBytes,
  isKnownErrorCode,
  MAX_LINE_BYTES,
  parseLine,
  type SidecarResponse,
} from "../src/sidecarProtocol.ts";

describe("encodeCommand", () => {
  test("one command is one newline terminated JSON object", () => {
    const line = encodeCommand({ id: 1, cmd: "connect", channel: 15 });
    assert.equal(line, '{"id":1,"cmd":"connect","channel":15}\n');
  });
});

describe("parseLine", () => {
  test("a response keeps its id, its code and its masked address", () => {
    const parsed = parseLine('{"id":7,"ok":true,"address":"XX:XX:XX:XX:EE:FF","channel":15}');
    assert.deepEqual(parsed, {
      id: 7,
      ok: true,
      error: undefined,
      code: undefined,
      detail: undefined,
      address: "XX:XX:XX:XX:EE:FF",
      errno: null,
      version: undefined,
      capabilities: undefined,
      method: undefined,
      channel: 15,
      matched_uuid: false,
      matched_serial: false,
    });
  });

  test("an SDP answer keeps the channel and the evidence behind it", () => {
    const parsed = parseLine(
      '{"id":3,"ok":true,"method":"sdptool","channel":18,"matched_uuid":true,"detail":"named"}',
    );
    if (!parsed || !("channel" in parsed)) throw new Error("the SDP answer did not parse");
    assert.equal(parsed.channel, 18);
    assert.equal(parsed.method, "sdptool");
    assert.equal(parsed.matched_uuid, true);
    assert.equal(parsed.matched_serial, false);
    assert.equal(parsed.detail, "named");
  });

  test("ping capabilities are parsed as strings", () => {
    const parsed = parseLine('{"id":9,"ok":true,"capabilities":["connect","write",4]}');
    assert.deepEqual(parsed && "capabilities" in parsed ? parsed.capabilities : null, ["connect", "write"]);
  });

  test("a failed response keeps its failure code and errno", () => {
    const parsed = parseLine('{"id":8,"ok":false,"code":"busy","error":"the watch is busy","errno":16}');
    assert.equal(parsed && "ok" in parsed ? parsed.ok : null, false);
    assert.equal(parsed && "code" in parsed ? parsed.code : null, "busy");
    assert.equal(parsed && "errno" in parsed ? parsed.errno : null, 16);
  });

  test("a data event is a count, a time and a channel, with no payload by default", () => {
    const parsed = parseLine('{"event":"data","bytes":37,"at":"2026-10-22T10:00:00Z","channel":15}');
    assert.deepEqual(parsed, {
      event: "data",
      bytes: 37,
      at: "2026-10-22T10:00:00Z",
      channel: 15,
      hex: undefined,
    });
  });

  test("hex is carried through when the sidecar was asked for it", () => {
    const parsed = parseLine('{"event":"data","bytes":2,"at":"t","hex":"0102"}');
    assert.equal(parsed && "hex" in parsed ? parsed.hex : null, "0102");
  });

  test("a closed event and an error event are told apart", () => {
    assert.deepEqual(parseLine('{"event":"closed","at":"t","reason":"the watch went away"}'), {
      event: "closed",
      at: "t",
      reason: "the watch went away",
    });
    assert.deepEqual(parseLine('{"event":"error","error":"reset","code":"reset","errno":104}'), {
      event: "error",
      error: "reset",
      code: "reset",
      errno: 104,
    });
  });

  test("anything unusable becomes null rather than a half message", () => {
    for (const line of [
      "",
      "   ",
      "not json",
      "[]",
      "null",
      "17",
      '{"event":"data","bytes":"lots","at":"t"}',
      '{"event":"error"}',
      '{"ok":true,"error":"no id at all"}',
    ]) {
      assert.equal(parseLine(line), null, `expected null for ${line}`);
    }
  });

  test("a python traceback on stdout does not become a message", () => {
    assert.equal(parseLine("Traceback (most recent call last):"), null);
  });
});

describe("hexToBytes", () => {
  test("hex becomes the bytes that arrived", () => {
    assert.deepEqual(hexToBytes("00ff10"), new Uint8Array([0x00, 0xff, 0x10]));
    assert.deepEqual(hexToBytes(""), new Uint8Array([]));
  });

  test("unusable hex is a broken pipe, not silent loss", () => {
    for (const bad of ["0", "zz", "0g", "01 02"]) {
      assert.throws(
        () => hexToBytes(bad),
        (err: unknown) => {
          assert.equal((err as { code?: string }).code, "protocol");
          return true;
        },
      );
    }
  });
});

describe("errorFromResponse", () => {
  test("a known code survives the trip", () => {
    const privateHex = "aabbccddeeff00112233445566778899";
    const err = errorFromResponse({ id: 1, ok: false, code: "busy", error: `busy ${privateHex}`, errno: 16 });
    assert.equal(err.code, "busy");
    assert.equal(err.errno, 16);
    assert.equal(err.message, "the link is busy");
    assert.equal(err.message.includes(privateHex), false);
  });

  test("an invented code becomes unknown instead of leaking into the caller", () => {
    const err = errorFromResponse({ id: 1, ok: false, code: "made-up", error: "?" });
    assert.equal(err.code, "unknown");
    assert.equal(err.errno, null);
  });

  test("a response with no message at all still says something useful", () => {
    const err = errorFromResponse({ id: 1, ok: false });
    assert.equal(err.message, "the sidecar reported an unknown error");
  });

  test("detail text is not copied into a thrown error", () => {
    const err = errorFromResponse({ id: 1, ok: false, code: "unsupported", detail: "Phase 4 owns the aux channel" });
    assert.equal(err.message, "the operation is unsupported");
  });

  test("the two Phase 3G codes map to their own sentences", () => {
    // The bond precondition and the refused secure link are different failures, so they must not
    // collapse into "permission" or "the link was refused".
    assert.equal(
      errorFromResponse({ id: 1, ok: false, code: "not-bonded" }).message,
      "the watch is not paired with this computer, and this run asked for a paired watch",
    );
    assert.equal(
      errorFromResponse({ id: 1, ok: false, code: "security-refused" }).message,
      "the Bluetooth stack refused the secure link; the watch is probably not bonded to this computer",
    );
  });
});

describe("dataCountOf", () => {
  test("a count with no channel is reported against channel 0 rather than dropped", () => {
    assert.deepEqual(dataCountOf({ event: "data", bytes: 4, at: "2026-10-22T10:00:00Z" }), {
      bytes: 4,
      at: "2026-10-22T10:00:00Z",
      channel: 0,
    });
  });

  test("the channel is carried through when the sidecar names it", () => {
    assert.deepEqual(dataCountOf({ event: "data", bytes: 4, at: "2026-10-22T10:00:00Z", channel: 15 }), {
      bytes: 4,
      at: "2026-10-22T10:00:00Z",
      channel: 15,
    });
  });

  test("payload-looking text in a timestamp is replaced before it can reach a logger", () => {
    const privateHex = "aabbccddeeff00112233445566778899";
    assert.deepEqual(dataCountOf({ event: "data", bytes: 16, at: privateHex }), {
      bytes: 16,
      at: "unknown time",
      channel: 0,
    });
  });
});

describe("isKnownErrorCode", () => {
  test("the codes the transport can throw are recognised", () => {
    for (const code of [
      "no-config",
      "write-not-allowed",
      "write-refused",
      "sidecar-exited",
      "unsupported",
      "not-bonded",
      "security-refused",
    ]) {
      assert.equal(isKnownErrorCode(code), true, code);
    }
  });

  test("anything else is not", () => {
    for (const value of ["", "Busy", "made-up", 17, null, undefined]) {
      assert.equal(isKnownErrorCode(value), false, String(value));
    }
  });
});

describe("MAX_LINE_BYTES", () => {
  test("there is a limit, and it is a megabyte", () => {
    assert.equal(MAX_LINE_BYTES, 1_048_576);
  });
});

describe("SidecarResponse", () => {
  test("the type accepts what the python side actually sends", () => {
    const response: SidecarResponse = { id: 1, ok: true, address: "XX:XX:XX:XX:EE:FF", channel: 5 };
    assert.equal(response.ok, true);
  });
});