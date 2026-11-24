// BCS helper — Phase 2 (codec) tests: CRC16. Every expected value here comes from Gadgetbridge's
// own test frames (see below); nothing is invented. No radio, no watch, no key material.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
// Ported from Gadgetbridge, app/src/test/java/nodomain/freeyourgadget/gadgetbridge/devices/huawei/
// TestHuaweiPacket.java (the frame CRCs) at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7, and
// util/CheckSums.java lines 59-73 for the algorithm this file re-checks independently.

import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { crc16, crc16Bytes, frameCrc16 } from "../src/huawei/crc16.ts";

const bytes = (hex: string): Uint8Array =>
  Uint8Array.from(hex.trim().split(/\s+/).map((part) => Number.parseInt(part, 16)));

/**
 * Independent bit-by-bit CRC-16/XMODEM (poly 0x1021, MSB-first, no reflection, no final XOR). It
 * exists to prove the ported loop is that variant rather than a loop tuned to pass five vectors.
 */
function naiveXmodem(seq: Uint8Array, init = 0x0000): number {
  let crc = init;
  for (const b of seq) {
    crc ^= (b & 0xff) << 8;
    for (let i = 0; i < 8; i += 1) {
      crc = (crc & 0x8000) !== 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc & 0xffff;
}

describe("crc16 — Gadgetbridge CheckSums.getCRC16 vectors", () => {
  // Each case is a Gadgetbridge test frame with the two CRC bytes it ends in, taken from
  // TestHuaweiPacket.java (the frame bytes are verbatim upstream vectors).
  const frameVectors: [string, string, number][] = [
    [
      "TestHuaweiPacket.testUnknownUnencryptedPacketParse",
      "5a 00 07 00 7f 7f 01 02 03 04",
      0x40b6,
    ],
    [
      "TestHuaweiPacket.testUnencryptedUnslicedSerialize",
      "5a 00 09 00 01 02 03 04 05 06 07 08",
      0xa4f0,
    ],
    ["TestHuaweiPacket.testUnencryptedSlicedSerialize slice 1", "5a 00 0b 01 00 01 02 01 04 00 00 00 00 02", 0xcc98],
    ["TestHuaweiPacket.testUnencryptedSlicedSerialize slice 2", "5a 00 0b 02 01 04 00 00 00 00 03 04 00 00", 0xfad3],
    ["TestHuaweiPacket.testUnencryptedSlicedSerialize slice 3", "5a 00 0a 03 02 00 00 04 04 00 00 00 00", 0x37ca],
  ];

  for (const [name, covered, expected] of frameVectors) {
    test(`${name}: CRC16 over the covered bytes is 0x${expected.toString(16)}`, () => {
      const coveredBytes = bytes(covered);
      assert.equal(frameCrc16(coveredBytes), expected);
      assert.equal(crc16(coveredBytes, 0x0000), expected);
      // The frame writes the checksum big-endian, so the low byte is the last of the pair.
      assert.deepEqual(crc16Bytes(coveredBytes), Uint8Array.of(expected >> 8, expected & 0xff));
    });
  }
});

describe("crc16 — the variant itself", () => {
  test("matches the independent bitwise CRC-16/XMODEM on every byte value", () => {
    const every = Uint8Array.from({ length: 256 }, (_, i) => i);
    assert.equal(frameCrc16(every), naiveXmodem(every));
    assert.equal(frameCrc16(new Uint8Array(0)), naiveXmodem(new Uint8Array(0)));
  });

  test("matches the independent implementation on seeded and random inputs", () => {
    let seed = 0x5a5a;
    const next = (): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed & 0xff;
    };
    for (let round = 0; round < 200; round += 1) {
      const length = next() % 64;
      const data = Uint8Array.from({ length }, next);
      assert.equal(frameCrc16(data), naiveXmodem(data, 0x0000));
      assert.equal(crc16(data, 0xffff), naiveXmodem(data, 0xffff));
    }
  });

  test("reproduces the published CRC-16/XMODEM check value for \"123456789\"", () => {
    const check = new TextEncoder().encode("123456789");
    assert.equal(frameCrc16(check), 0x31c3);
    assert.equal(frameCrc16(check), naiveXmodem(check));
  });

  test("crc16Bytes takes a seed, and its default seed is the frame's 0x0000", () => {
    const data = bytes("5a 00 07 00 7f 7f 01 02 03 04");
    assert.deepEqual(crc16Bytes(data), crc16Bytes(data, 0x0000));
    assert.notDeepEqual(crc16Bytes(data, 0xffff), crc16Bytes(data, 0x0000));
  });
});
