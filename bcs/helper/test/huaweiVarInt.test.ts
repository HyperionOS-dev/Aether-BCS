// BCS helper — Phase 2 (codec) tests: the 7-bit VarInt. Expected values are Gadgetbridge's own
// TestVarInt vectors, ported byte for byte. No radio, no watch, no key material.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
// Ported from Gadgetbridge, app/src/test/java/nodomain/freeyourgadget/gadgetbridge/devices/huawei/
// TestVarInt.java at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7: lines 22-72, the VarInt
// vectors, byte for byte.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { MAX_VARINT_BYTES, encodeVarInt, readVarInt, varIntSize } from "../src/huawei/varint.ts";

/** TestVarInt.java lines 24-33: one value checked four ways, exactly as upstream does. */
function testValue(intValue: number, bytesValue: Uint8Array, size: number): void {
  assert.equal(varIntSize(intValue), size, `size of ${intValue}`);
  const decoded = readVarInt(bytesValue, 0);
  assert.equal(decoded.ok, true, `decode of ${intValue}`);
  if (!decoded.ok) return;
  assert.equal(decoded.value.value, intValue);
  assert.equal(decoded.value.size, size);
  assert.deepEqual(encodeVarInt(intValue), bytesValue, `encode of ${intValue}`);
}

describe("varint — Gadgetbridge TestVarInt vectors", () => {
  test("testZero: 0 -> [0], one byte", () => {
    testValue(0, Uint8Array.of(0), 1);
  });

  test("testSingleValue: 17 -> [11], one byte", () => {
    testValue(17, Uint8Array.of(17), 1);
  });

  test("test0x80: 128 -> [81, 00], two bytes (the first overflowing value)", () => {
    testValue(0x80, Uint8Array.of(0x81, 0x00), 2);
  });

  test("testDoubleValue: 460 -> [83, 4C], two bytes", () => {
    testValue(460, Uint8Array.of(0x83, 0x4c), 2);
  });

  test("testOffset: 460 decoded from offset 1 of [00, 83, 4C]", () => {
    const intValue = 460;
    const bytesValue = Uint8Array.of(0x83, 0x4c);
    const bytesTest = Uint8Array.of(0x00, 0x83, 0x4c);

    assert.equal(varIntSize(intValue), 2);
    const decoded = readVarInt(bytesTest, 1);
    assert.equal(decoded.ok, true);
    if (!decoded.ok) return;
    assert.equal(decoded.value.value, intValue);
    assert.equal(decoded.value.size, 2);
    assert.deepEqual(encodeVarInt(intValue), bytesValue);
  });
});

describe("varint — the encoding boundaries TLV lengths sit on", () => {
  // A TLV value length of 127 is one byte, 128 needs two: that is the edge the format turns on.
  const boundaries: [number, number][] = [
    [0, 1],
    [1, 1],
    [127, 1],
    [128, 2],
    [16383, 2],
    [16384, 3],
    [0xffff, 3],
    [0xfffff, 3],
    [0x100000, 3], // 2^20 needs 21 bits, which is still three 7-bit groups
    [0x200000, 4], // 2^21 is the first value that needs four
  ];

  for (const [value, size] of boundaries) {
    test(`${value} encodes in ${size} byte(s) and round-trips`, () => {
      const encoded = encodeVarInt(value);
      assert.equal(encoded.length, size);
      assert.equal(varIntSize(value), size);
      const decoded = readVarInt(encoded, 0);
      assert.equal(decoded.ok, true);
      if (!decoded.ok) return;
      assert.equal(decoded.value.value, value);
      assert.equal(decoded.value.size, size);
    });
  }

  test("every byte of a multi-byte value except the last carries the continuation bit", () => {
    const encoded = encodeVarInt(0xffffff); // 24 bits: 3 + 7 + 7 + 7 across four bytes
    assert.equal(encoded.length, 4);
    assert.deepEqual(encoded, Uint8Array.of(0x87, 0xff, 0xff, 0x7f));
    assert.equal(encoded[0] & 0x80, 0x80);
    assert.equal(encoded[1] & 0x80, 0x80);
    assert.equal(encoded[2] & 0x80, 0x80);
    assert.equal(encoded[3] & 0x80, 0x00);
  });

  test("the shortest form is always used, so re-encoding is stable", () => {
    for (const value of [0, 5, 200, 70000]) {
      const once = encodeVarInt(value);
      const decoded = readVarInt(once, 0);
      assert.equal(decoded.ok, true);
      if (!decoded.ok) return;
      assert.deepEqual(encodeVarInt(decoded.value.value), once);
    }
  });
});

describe("varint — malformed input returns a typed error, never a throw", () => {
  test("a value that never terminates is bad-tlv", () => {
    const endless = new Uint8Array(8).fill(0xff);
    const result = readVarInt(endless, 0);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.error.code, "bad-tlv");
    assert.equal(MAX_VARINT_BYTES, 5);
  });

  test("a value whose last byte is missing is truncated", () => {
    const short = Uint8Array.of(0x81); // continuation bit set, nothing after it
    const result = readVarInt(short, 0);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.error.code, "truncated");
  });

  test("an offset at or past the end is truncated, not a crash", () => {
    const single = Uint8Array.of(0x7f);
    const valid = readVarInt(single, 0);
    assert.equal(valid.ok, true); // offset 0 of a one-byte buffer is a valid read
    for (const offset of [1, 2, 99]) {
      const result = readVarInt(single, offset);
      assert.equal(result.ok, false, `offset ${offset}`);
      if (result.ok) return;
      assert.equal(result.error.code, "truncated");
    }
  });
});
