// BCS helper — Phase 2 (codec) tests: reassembly across split and merged reads. The fixtures are
// frames the encoder builds from Gadgetbridge's wire layout, and the split points are generated
// rather than invented constants. No radio, no watch, no key material, no health data.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
// Ported from Gadgetbridge, app/src/main/java/nodomain/freeyourgadget/gadgetbridge/devices/huawei/
// HuaweiPacket.java at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7: lines 321-361, 375 and
// 388-402, the reassembly rules these tests exercise.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { HuaweiTlv } from "../src/huawei/tlv.ts";
import { encodeFrame } from "../src/huawei/frame.ts";
import { createHuaweiStream, decodeFrames } from "../src/huawei/stream.ts";

const ok = <T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!result.ok) throw new Error("expected success");
  return result.value;
};
const known = new Set([
  "bad-magic",
  "bad-length",
  "bad-crc",
  "truncated",
  "bad-tlv",
  "bad-value",
  "missing-tag",
  "bad-argument",
  "unsupported",
]);

/** A small unsliced frame, the shape of the upstream unsliced vector, built by our encoder. */
function oneFrame(): Uint8Array[] {
  return ok(
    encodeFrame({
      serviceId: 0x01,
      commandId: 0x02,
      tlv: new HuaweiTlv().putInt(0x03, 0x05060708),
      sliced: false,
      isEncrypted: false,
    }),
  );
}

/** A sliced packet: three frames, the shape of the upstream sliced vector. */
function slicedFrames(): Uint8Array[] {
  return ok(
    encodeFrame({
      serviceId: 0x01,
      commandId: 0x02,
      tlv: new HuaweiTlv().putInt(0x01, 0x00).putInt(0x02, 0x00).putInt(0x03, 0x00).putInt(0x04, 0x00),
      sliced: true,
      sliceSize: 0x10,
      isEncrypted: false,
    }),
  );
}

describe("stream — one frame split at every possible byte offset", () => {
  const frame = oneFrame()[0];

  for (let cut = 1; cut < frame.length; cut += 1) {
    test(`split after byte ${cut} of ${frame.length} reassembles the frame`, () => {
      const stream = createHuaweiStream();
      const first = stream.push(frame.subarray(0, cut));
      assert.deepEqual(first.frames, []);
      assert.equal(first.error, undefined);
      assert.equal(stream.pendingBytes(), cut);

      const second = stream.push(frame.subarray(cut));
      assert.equal(second.error, undefined);
      assert.equal(second.frames.length, 1);
      assert.equal(second.frames[0].serviceId, 0x01);
      assert.equal(second.frames[0].commandId, 0x02);
      assert.deepEqual(second.frames[0].payload, frame.subarray(4, frame.length - 2));
      assert.equal(stream.pendingBytes(), 0);
      assert.equal(stream.end().error, undefined);
    });
  }

  test("fed one byte at a time, the same frame still comes out exactly once", () => {
    const stream = createHuaweiStream();
    const frames = [];
    for (const byte of frame) {
      const step = stream.push(Uint8Array.of(byte));
      assert.equal(step.error, undefined);
      frames.push(...step.frames);
    }
    assert.equal(frames.length, 1);
    assert.deepEqual(frames[0].payload, frame.subarray(4, frame.length - 2));
    assert.equal(stream.pendingBytes(), 0);
  });
});

describe("stream — several frames arriving together", () => {
  test("two frames in one read produce two frames in one push", () => {
    const frame = oneFrame()[0];
    const step = createHuaweiStream().push(Uint8Array.from([...frame, ...frame]));
    assert.equal(step.error, undefined);
    assert.equal(step.frames.length, 2);
    assert.equal(step.pendingBytes, 0);
  });

  test("three frames split unevenly across four reads still produce three frames", () => {
    const frame = oneFrame()[0];
    const all = Uint8Array.from([...frame, ...frame, ...frame]);
    const stream = createHuaweiStream();
    let previous = 0;
    const frames = [];
    for (const cut of [1, 5, 13, all.length]) {
      const step = stream.push(all.subarray(previous, cut));
      previous = cut;
      assert.equal(step.error, undefined);
      frames.push(...step.frames);
    }
    assert.equal(frames.length, 3);
    assert.equal(stream.pendingBytes(), 0);
  });
});

describe("stream — sliced packets are assembled, however they arrive", () => {
  const frames = slicedFrames();

  test("the upstream sliced vector's three slices arrive as one frame", () => {
    assert.equal(frames.length, 3);
    const stream = createHuaweiStream();
    assert.deepEqual(stream.push(frames[0]).frames, []);
    assert.equal(stream.pendingBytes() > 0, true);
    assert.deepEqual(stream.push(frames[1]).frames, []);
    const third = stream.push(frames[2]);
    assert.equal(third.frames.length, 1);
    assert.equal(third.frames[0].sliceCount, 3);
    assert.deepEqual(third.frames[0].sliceFlags, [0, 1, 2]);
    assert.equal(stream.pendingBytes(), 0);
  });

  test("the same three slices fed one byte at a time give the same single frame", () => {
    const stream = createHuaweiStream();
    const joined = Uint8Array.from(frames.flatMap((f) => [...f]));
    const out = [];
    for (const byte of joined) {
      const step = stream.push(Uint8Array.of(byte));
      assert.equal(step.error, undefined);
      out.push(...step.frames);
    }
    assert.equal(out.length, 1);
    assert.equal(out[0].serviceId, 0x01);
    assert.equal(out[0].commandId, 0x02);
    assert.equal(out[0].sliceCount, 3);
  });

  test("a whole sliced packet in one read decodes to one frame with its TLV intact", () => {
    const joined = Uint8Array.from(frames.flatMap((f) => [...f]));
    const decoded = ok(decodeFrames(joined));
    assert.equal(decoded.length, 1);
    assert.deepEqual(
      decoded[0].tlv?.serialize(),
      new HuaweiTlv()
        .putInt(0x01, 0x00)
        .putInt(0x02, 0x00)
        .putInt(0x03, 0x00)
        .putInt(0x04, 0x00)
        .serialize(),
    );
  });

  test("a middle slice with no first slice is a typed error, not an invented frame", () => {
    const step = createHuaweiStream().push(frames[1]); // slice 0x02 with nothing before it
    assert.equal(step.frames.length, 0);
    assert.equal(step.error?.code, "bad-length");
  });

  test("a fresh first slice replaces an unfinished packet instead of merging with it", () => {
    // Documented divergence from upstream, which appends and would invent one payload from two.
    const stream = createHuaweiStream();
    assert.deepEqual(stream.push(frames[0]).frames, []);
    const rest = stream.push(Uint8Array.from([...frames[0], ...frames[1], ...frames[2]]));
    assert.equal(rest.error, undefined);
    assert.equal(rest.frames.length, 1);
    assert.equal(rest.frames[0].sliceCount, 3);
  });
});

describe("stream — errors, truncation and the buffer ceiling", () => {
  test("a good frame followed by garbage delivers the frame and reports the error", () => {
    const frame = oneFrame()[0];
    const step = createHuaweiStream().push(Uint8Array.from([...frame, 0x00, 0x00, 0x00, 0x00]));
    assert.equal(step.frames.length, 1, "the frame that did arrive is still reported");
    assert.equal(step.error?.code, "bad-magic");
    assert.equal(step.pendingBytes, 0, "the buffer is cleared so the next read starts clean");
  });

  test("a CRC failure clears the buffer", () => {
    const frame = new Uint8Array(oneFrame()[0]);
    frame[frame.length - 1] ^= 0xff;
    const stream = createHuaweiStream();
    assert.equal(stream.push(frame).error?.code, "bad-crc");
    assert.equal(stream.pendingBytes(), 0);
  });

  test("end() reports truncation when bytes are left over", () => {
    const stream = createHuaweiStream();
    assert.deepEqual(stream.push(oneFrame()[0].subarray(0, 4)).frames, []);
    assert.equal(stream.end().error?.code, "truncated");
  });

  test("end() is quiet after a whole frame, and after an empty stream", () => {
    const stream = createHuaweiStream();
    stream.push(oneFrame()[0]);
    assert.equal(stream.end().error, undefined);
    assert.equal(createHuaweiStream().end().error, undefined);
  });

  test("end() inside a sliced packet is truncated", () => {
    const stream = createHuaweiStream();
    stream.push(slicedFrames()[0]);
    assert.equal(stream.end().error?.code, "truncated");
  });

  test("pushing nothing is not an error and changes nothing", () => {
    const step = createHuaweiStream().push(new Uint8Array(0));
    assert.deepEqual(step.frames, []);
    assert.equal(step.error, undefined);
    assert.equal(step.pendingBytes, 0);
  });

  test("a buffer that can never be framed hits the ceiling instead of growing forever", () => {
    const stream = createHuaweiStream({ maxPendingBytes: 32 });
    const step = stream.push(new Uint8Array([0x5a, 0x7f, 0xff, ...new Uint8Array(40).fill(0x11)]));
    assert.equal(step.error?.code, "bad-length");
    assert.equal(stream.pendingBytes(), 0);
  });

  test("reset() throws away a half-received frame", () => {
    const frame = oneFrame()[0];
    const stream = createHuaweiStream();
    stream.push(frame.subarray(0, 5));
    assert.equal(stream.pendingBytes() > 0, true);
    stream.reset();
    assert.equal(stream.pendingBytes(), 0);
    assert.equal(stream.push(frame).frames.length, 1);
  });

  test("decodeFrames insists on whole frames: a stray byte is truncated", () => {
    const frame = oneFrame()[0];
    assert.equal(ok(decodeFrames(frame)).length, 1);
    assert.equal(decodeFrames(new Uint8Array([...frame, 0x5a])).ok, false);
  });

  test("random garbage never throws and never invents a frame", () => {
    let seed = 0x0b5c0de;
    const next = (): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed & 0xff;
    };
    for (let round = 0; round < 300; round += 1) {
      const stream = createHuaweiStream();
      const chunks = 1 + (next() % 4);
      for (let c = 0; c < chunks; c += 1) {
        const chunk = Uint8Array.from({ length: next() % 24 }, next);
        const step = stream.push(chunk);
        for (const frame of step.frames) {
          // A frame is only ever handed out with valid byte-valued ids.
          assert.ok(frame.serviceId >= 0 && frame.serviceId <= 255);
          assert.ok(frame.commandId >= 0 && frame.commandId <= 255);
        }
        if (step.error) assert.ok(known.has(step.error.code), `unexpected code ${step.error.code}`);
      }
      const ended = stream.end();
      if (ended.error) assert.ok(known.has(ended.error.code));
    }
  });
});
