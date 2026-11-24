// BCS helper — Phase 2 (codec) tests: the Huawei TLV. Every expected value is a Gadgetbridge
// TestHuaweiTLV vector, ported byte for byte; nothing here is invented. No radio, no watch, no key
// material, and no health data.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
// Ported from Gadgetbridge, app/src/test/java/nodomain/freeyourgadget/gadgetbridge/devices/huawei/
// TestHuaweiTLV.java at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7: lines 59-532, the TLV
// vectors, byte for byte.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { HuaweiTlv } from "../src/huawei/tlv.ts";

const bytes = (...values: number[]): Uint8Array => Uint8Array.from(values);
const entries = (tlv: HuaweiTlv): { tag: number; value: number[] }[] =>
  tlv.entries.map((entry) => ({ tag: entry.tag, value: [...entry.value] }));
const ok = <T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!result.ok) throw new Error("expected success");
  return result.value;
};

describe("HuaweiTlv — TestHuaweiTLV serialisation vectors", () => {
  test("testSerializeEmpty: an empty TLV serialises to zero bytes", () => {
    assert.deepEqual(new HuaweiTlv().serialize(), bytes());
  });

  test("testSerialize: [01 00] then [01 01 42]", () => {
    const tlv = new HuaweiTlv();
    tlv.entries.push({ tag: 0x01, value: bytes() });
    tlv.entries.push({ tag: 0x01, value: bytes(0x42) });
    assert.deepEqual(tlv.serialize(), bytes(0x01, 0x00, 0x01, 0x01, 0x42));
  });

  test("testPutEmptyTag: put(tag) adds an empty value", () => {
    assert.deepEqual(entries(new HuaweiTlv().putEmpty(0x01)), [{ tag: 0x01, value: [] }]);
  });

  test("testPutNullByteArray: a null value adds nothing at all", () => {
    assert.deepEqual(entries(new HuaweiTlv().putBytes(0x01, null)), []);
  });

  test("testPutByteArray", () => {
    assert.deepEqual(entries(new HuaweiTlv().putBytes(0x01, bytes(0x01, 0x02, 0x03))), [
      { tag: 0x01, value: [0x01, 0x02, 0x03] },
    ]);
  });

  test("testPutByte", () => {
    assert.deepEqual(entries(new HuaweiTlv().putByte(0x01, 0x13)), [{ tag: 0x01, value: [0x13] }]);
  });

  test("testPutBooleans: true is 01, false is 00", () => {
    const tlv = new HuaweiTlv().putBoolean(0x01, true).putBoolean(0x02, false);
    assert.deepEqual(entries(tlv), [
      { tag: 0x01, value: [0x01] },
      { tag: 0x02, value: [0x00] },
    ]);
  });

  test("testPutInt: 0xDEADBEEF is four big-endian bytes", () => {
    assert.deepEqual(entries(new HuaweiTlv().putInt(0x01, 0xdeadbeef)), [
      { tag: 0x01, value: [0xde, 0xad, 0xbe, 0xef] },
    ]);
  });

  test("testPutShort: 0xCAFE is two big-endian bytes", () => {
    assert.deepEqual(entries(new HuaweiTlv().putShort(0x01, 0xcafe)), [
      { tag: 0x01, value: [0xca, 0xfe] },
    ]);
    // A negative short is the same two bytes on the wire, as in Java.
    assert.deepEqual(entries(new HuaweiTlv().putShort(0x01, -13570)), [
      { tag: 0x01, value: [0xca, 0xfe] },
    ]);
  });

  test("testPutString: UTF-8 bytes", () => {
    assert.deepEqual(entries(new HuaweiTlv().putString(0x01, "Hello world!")), [
      { tag: 0x01, value: [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21] },
    ]);
  });

  test("testPutHuaweiTLV: a nested TLV is the serialised inner TLV", () => {
    const inner = new HuaweiTlv().putShort(0x01, 0x1337);
    assert.deepEqual(entries(new HuaweiTlv().putTlv(0x01, inner)), [
      { tag: 0x01, value: [0x01, 0x02, 0x13, 0x37] },
    ]);
  });

  test("testPutMultipleEqualEmptyTags: the same tag may repeat", () => {
    assert.deepEqual(entries(new HuaweiTlv().putEmpty(0x01).putEmpty(0x01)), [
      { tag: 0x01, value: [] },
      { tag: 0x01, value: [] },
    ]);
  });

  test("length() is the sum of tag + VarInt length + value", () => {
    const tlv = new HuaweiTlv().putBytes(0x01, bytes(0x01, 0x02, 0x03));
    assert.equal(tlv.length(), 5);
    assert.equal(tlv.serialize().length, 5);
    // A value of 128 bytes crosses the VarInt boundary: 1 tag + 2 length + 128.
    const wide = new HuaweiTlv().putBytes(0x01, new Uint8Array(128));
    assert.equal(wide.length(), 131);
    assert.deepEqual(wide.serialize().subarray(0, 3), bytes(0x01, 0x81, 0x00));
  });
});

describe("HuaweiTlv — TestHuaweiTLV parse vectors", () => {
  test("testParseEmpty: nothing in, nothing out", () => {
    const parsed = ok(HuaweiTlv.from(bytes()));
    assert.deepEqual(entries(parsed), []);
  });

  test("testParseSingleByte: [01 01 01]", () => {
    const parsed = ok(HuaweiTlv.from(bytes(0x01, 0x01, 0x01)));
    assert.deepEqual(entries(parsed), [{ tag: 0x01, value: [0x01] }]);
  });

  test("testParseBytes: [01 04 DE AD BE EF]", () => {
    const parsed = ok(HuaweiTlv.from(bytes(0x01, 0x04, 0xde, 0xad, 0xbe, 0xef)));
    assert.deepEqual(entries(parsed), [{ tag: 0x01, value: [0xde, 0xad, 0xbe, 0xef] }]);
  });

  test("testParseZeroOffsetLength: offset 0 length 0 parses nothing", () => {
    const parsed = ok(new HuaweiTlv().parse(bytes(), 0, 0));
    assert.deepEqual(entries(parsed), []);
  });

  test("testParseOffsetLength: [90 90 90 | 01 00], offset 3 length 2", () => {
    const parsed = ok(HuaweiTlv.from(bytes(0x90, 0x90, 0x90, 0x01, 0x00), 3, 2));
    assert.deepEqual(entries(parsed), [{ tag: 0x01, value: [] }]);
  });

  test("testParseMalformed: [01 01] is a typed error, not a crash", () => {
    // Upstream expects ArrayIndexOutOfBoundsException here (TestHuaweiTLV:261-266).
    const parsed = HuaweiTlv.from(bytes(0x01, 0x01));
    assert.equal(parsed.ok, false);
    if (parsed.ok) return;
    assert.equal(parsed.error.code, "bad-tlv");
    assert.equal(parsed.error.name, "HuaweiCodecError");
  });

  test("testParseWrongOffsetLength: a range outside the buffer is a typed error", () => {
    // Upstream expects ArrayIndexOutOfBoundsException here too (TestHuaweiTLV:283-288).
    const parsed = HuaweiTlv.from(bytes(), 1, 1);
    assert.equal(parsed.ok, false);
    if (parsed.ok) return;
    assert.equal(parsed.error.code, "bad-tlv");
  });

  test("a two-byte VarInt length is honoured (a value of 128 bytes)", () => {
    const wide = new HuaweiTlv().putBytes(0x01, new Uint8Array(128).fill(0x5a));
    const parsed = ok(HuaweiTlv.from(wide.serialize()));
    assert.equal(parsed.getBytes(0x01).length, 128);
    assert.deepEqual(parsed.serialize(), wide.serialize());
  });

  test("a value that runs past the end is a typed error", () => {
    const parsed = HuaweiTlv.from(bytes(0x01, 0x04, 0xde, 0xad));
    assert.equal(parsed.ok, false);
    if (parsed.ok) return;
    assert.equal(parsed.error.code, "bad-tlv");
  });

  test("a lone trailing 00 tag is ignored: the upstream encrypted-payload rule", () => {
    const parsed = ok(HuaweiTlv.from(bytes(0x01, 0x01, 0x42, 0x00)));
    assert.deepEqual(entries(parsed), [{ tag: 0x01, value: [0x42] }]);
  });

  test("parse appends to what the TLV already holds", () => {
    const tlv = new HuaweiTlv().putByte(0x09, 0x01);
    ok(tlv.parse(bytes(0x02, 0x01, 0x02)));
    assert.deepEqual(entries(tlv), [
      { tag: 0x09, value: [0x01] },
      { tag: 0x02, value: [0x02] },
    ]);
  });
});

describe("HuaweiTlv — TestHuaweiTLV reader vectors", () => {
  const withEntry = (tag: number, value: number[]): HuaweiTlv => {
    const tlv = new HuaweiTlv();
    tlv.entries.push({ tag, value: bytes(...value) });
    return tlv;
  };

  test("testGetBytesEmpty / testGetBytes", () => {
    assert.deepEqual(withEntry(0x01, []).getBytes(0x01), bytes());
    assert.deepEqual(withEntry(0x01, [0x01, 0x02, 0x03]).getBytes(0x01), bytes(0x01, 0x02, 0x03));
  });

  test("testGetByte", () => {
    assert.equal(withEntry(0x01, [0x04]).getByte(0x01), 0x04);
  });

  test("testGetBooleans", () => {
    const tlv = withEntry(0x01, [0x01]);
    tlv.entries.push({ tag: 0x02, value: bytes(0x00) });
    assert.equal(tlv.getBoolean(0x01), true);
    assert.equal(tlv.getBoolean(0x02), false);
  });

  test("testGetInteger: 0xDEADBEEF reads as signed 32-bit, exactly as Java's Integer does", () => {
    const value = withEntry(0x01, [0xde, 0xad, 0xbe, 0xef]);
    assert.equal(value.getInteger(0x01), -559038737);
    assert.equal(value.getInteger(0x01) >>> 0, 0xdeadbeef);
  });

  test("testGetShort: (short) 0xCAFE is -13570", () => {
    assert.equal(withEntry(0x01, [0xca, 0xfe]).getShort(0x01), -13570);
  });

  test("testGetString: UTF-8 again", () => {
    const value = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21];
    assert.equal(withEntry(0x01, value).getString(0x01), "Hello world!");
  });

  test("testGetObject: [01 00] is a nested TLV holding one empty tag", () => {
    const nested = ok(withEntry(0x01, [0x01, 0x00]).tryGetObject(0x01));
    assert.deepEqual(entries(nested), entries(new HuaweiTlv().putEmpty(0x01)));
  });

  test("getObjects returns every entry with that tag, each parsed", () => {
    const tlv = new HuaweiTlv();
    tlv.entries.push({ tag: 0x81, value: bytes(0x01, 0x00) });
    tlv.entries.push({ tag: 0x81, value: bytes(0x02, 0x01, 0x05) });
    const objects = ok(tlv.tryGetObjects(0x81));
    assert.equal(objects.length, 2);
    assert.deepEqual(entries(objects[0]), [{ tag: 0x01, value: [] }]);
    assert.deepEqual(entries(objects[1]), [{ tag: 0x02, value: [0x05] }]);
  });

  test("a missing tag is a typed missing-tag error, and the DEFAULT forms are quiet", () => {
    const tlv = withEntry(0x01, [0x04]);
    const missing = tlv.tryGetBytes(0x02);
    assert.equal(missing.ok, false);
    if (missing.ok) return;
    assert.equal(missing.error.code, "missing-tag");
    assert.throws(() => tlv.getBytes(0x02), (error: { code?: string }) => error.code === "missing-tag");
    assert.deepEqual(tlv.getBytesOrDefault(0x02, bytes(0xff)), bytes(0xff));
    assert.equal(tlv.getByteOrDefault(0x02, 0x07), 0x07);
    assert.equal(tlv.getShortOrDefault(0x02, 0x07), 0x07);
    assert.equal(tlv.getBooleanOrDefault(0x02, true), true);
    assert.equal(tlv.getIntegerOrDefault(0x02, 0x07), 0x07);
    assert.equal(tlv.getAsInteger(0x01), 0x04);
  });

  test("a typed getter on a value of the wrong size is bad-value, not a crash", () => {
    const short = withEntry(0x01, [0x04]);
    const result = short.tryGetInteger(0x01);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.error.code, "bad-value");
    assert.equal(short.tryGetShort(0x01).ok, false);
    assert.equal(short.tryGetLong(0x01).ok, false);
    assert.equal(withEntry(0x01, []).tryGetByte(0x01).ok, false);
    // getAsInteger on three bytes is the case upstream would throw BufferUnderflowException on.
    assert.equal(withEntry(0x01, [0x01, 0x02, 0x03]).tryGetAsInteger(0x01).ok, false);
  });

  test("getAsInteger: one byte is unsigned, two are unsigned, four are signed", () => {
    assert.equal(withEntry(0x01, [0xff]).getAsInteger(0x01), 255);
    assert.equal(withEntry(0x01, [0xff, 0xff]).getAsInteger(0x01), 65535);
    assert.equal(withEntry(0x01, [0xde, 0xad, 0xbe, 0xef]).getAsInteger(0x01), -559038737);
  });

  test("getLong reads eight big-endian bytes; putLong writes the same eight", () => {
    assert.equal(withEntry(0x01, [0, 0, 0, 0, 0, 0, 0, 0x2a]).getLong(0x01), 42n);
    assert.deepEqual(entries(new HuaweiTlv().putLong(0x01, 42n)), [
      { tag: 0x01, value: [0, 0, 0, 0, 0, 0, 0, 0x2a] },
    ]);
  });

  test("putDouble writes eight little-endian bytes, as upstream's ByteOrder.LITTLE_ENDIAN does", () => {
    assert.deepEqual(entries(new HuaweiTlv().putDouble(0x01, 1)), [
      { tag: 0x01, value: [0, 0, 0, 0, 0, 0, 0xf0, 0x3f] },
    ]);
  });
});

describe("HuaweiTlv — TestHuaweiTLV contains / remove / toString vectors", () => {
  test("testContains", () => {
    assert.equal(new HuaweiTlv().putEmpty(0x01).contains(0x01), true);
    assert.equal(new HuaweiTlv().putEmpty(0x01).contains(0x02), false);
  });

  test("testRemoveExisting: removes the tag and returns its value", () => {
    const tlv = new HuaweiTlv().putBytes(0x01, bytes(0x13, 0x37)).putEmpty(0x02);
    assert.deepEqual(tlv.remove(0x01), bytes(0x13, 0x37));
    assert.deepEqual(entries(tlv), [{ tag: 0x02, value: [] }]);
  });

  test("testRemoveNonExisting: null, and the TLV is untouched", () => {
    const tlv = new HuaweiTlv().putBytes(0x01, bytes(0x13, 0x37));
    assert.equal(tlv.remove(0x02), null);
    assert.deepEqual(entries(tlv), [{ tag: 0x01, value: [0x13, 0x37] }]);
  });

  test("testRemoveDouble: the last matching tag goes first", () => {
    const tlv = new HuaweiTlv().putByte(0x01, 0xca).putByte(0x01, 0xfe);
    assert.deepEqual(tlv.remove(0x01), bytes(0xfe));
    assert.deepEqual(entries(tlv), [{ tag: 0x01, value: [0xca] }]);
    assert.deepEqual(tlv.remove(0x01), bytes(0xca));
    assert.deepEqual(entries(tlv), []);
  });

  test("testToStringEmpty: 'Empty'", () => {
    assert.equal(new HuaweiTlv().toString(), "Empty");
  });

  test("testToString: '{tag: 1 - Value: 0102} - {tag: 2 - Value: 0304}'", () => {
    const tlv = new HuaweiTlv().putBytes(0x01, bytes(0x01, 0x02)).putBytes(0x02, bytes(0x03, 0x04));
    assert.equal(tlv.toString(), "{tag: 1 - Value: 0102} - {tag: 2 - Value: 0304}");
  });

  test("equals compares the entry list, as upstream's HuaweiTLV.equals does", () => {
    const same = new HuaweiTlv().putByte(0x01, 0x02);
    assert.equal(same.equals(new HuaweiTlv().putByte(0x01, 0x02)), true);
    assert.equal(same.equals(new HuaweiTlv().putByte(0x01, 0x03)), false);
    assert.equal(same.equals(null), false);
  });

  test("the encrypted envelope of TestHuaweiTLV.testEncrypt round-trips with no crypto at all", () => {
    // TestHuaweiTLV:492-509 expects encrypt() to build exactly these three tags. Phase 2 never
    // decrypts, but the envelope it will meet must parse and re-serialise byte for byte.
    const ciphertext = bytes(
      0x0e, 0xa0, 0x01, 0xbb, 0x1e, 0xda, 0xcb, 0x09, 0x83, 0x20, 0x40, 0x7d, 0x97, 0x1b, 0xf6, 0xd0,
    );
    const envelope = new HuaweiTlv()
      .putByte(0x7c, 0x01)
      .putBytes(0x7d, new Uint8Array(16))
      .putBytes(0x7e, ciphertext);
    const reparsed = ok(HuaweiTlv.from(envelope.serialize()));
    assert.deepEqual(entries(reparsed), entries(envelope));
    assert.deepEqual(reparsed.serialize(), envelope.serialize());
    assert.equal(reparsed.getBoolean(0x7c), true);
    assert.equal(reparsed.getBytes(0x7d).length, 16);
    assert.deepEqual(reparsed.getBytes(0x7e), ciphertext);
  });
});
