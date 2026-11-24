// BCS helper — Phase 2 (codec) tests: the frame. The inputs and the expected frames are
// Gadgetbridge's own TestHuaweiPacket vectors, ported byte for byte. No radio, no watch, no key
// material, no health data.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
// Ported from Gadgetbridge, app/src/test/java/nodomain/freeyourgadget/gadgetbridge/devices/huawei/
// TestHuaweiPacket.java at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7: lines 19-269, the five
// frame vectors, byte for byte, plus their input TLVs.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { HuaweiTlv } from "../src/huawei/tlv.ts";
import { frameCrc16 } from "../src/huawei/crc16.ts";
import {
  decodeOneFrame,
  encodeFrame,
  serializeSliced,
  serializeUnsliced,
} from "../src/huawei/frame.ts";
import { decodeFrames } from "../src/huawei/stream.ts";
import { NON_TLV_PACKETS } from "../src/huawei/constants.ts";

const bytes = (...values: number[]): Uint8Array => Uint8Array.from(values);
const hex = (text: string): Uint8Array =>
  Uint8Array.from(text.trim().split(/\s+/).map((part) => Number.parseInt(part, 16)));
const entriesOf = (tlv: HuaweiTlv | null): { tag: number; value: number[] }[] =>
  tlv === null ? [] : tlv.entries.map((entry) => ({ tag: entry.tag, value: [...entry.value] }));
const ok = <T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!result.ok) throw new Error("expected success");
  return result.value;
};
const errorCode = (result: { ok: true } | { ok: false; error: { code: string } }): string => {
  if (result.ok) throw new Error("expected a typed error");
  return result.error.code;
};

describe("frame — TestHuaweiPacket parse vectors", () => {
  test("testEmptyPacketParse: an empty buffer is a length mismatch, not a crash", () => {
    // Upstream expects LengthMismatchException here (TestHuaweiPacket:20-32).
    const step = decodeOneFrame(bytes());
    assert.equal(step.ok, false);
    if (step.ok) return;
    assert.equal(step.error.code, "bad-length");
    assert.equal(step.error.name, "HuaweiCodecError");
  });

  test("testUnknownUnencryptedPacketParse: 5a 00 07 00 7f 7f 01 02 03 04 40 b6", () => {
    const frame = ok(decodeFrames(hex("5a 00 07 00 7f 7f 01 02 03 04 40 b6")))[0];
    assert.equal(frame.serviceId, 0x7f);
    assert.equal(frame.commandId, 0x7f);
    assert.equal(frame.encryptedEnvelope, false);
    assert.equal(frame.sliceType, 0);
    assert.equal(frame.sliceCount, 1);
    assert.deepEqual(entriesOf(frame.tlv), entriesOf(new HuaweiTlv().putShort(0x01, 0x0304)));
    // The payload is the id bytes plus the TLV, as upstream keeps it (HuaweiPacket.java:404-420).
    assert.deepEqual(frame.payload, hex("7f 7f 01 02 03 04"));
  });

  test("testUnknownEncryptedPacketParse: the 7C/7D/7E envelope is recognised, never opened", () => {
    // TestHuaweiPacket:53-68 asserts that this decrypts to TLV {0x01: (short) 0x0304} with the
    // all-zero key its provider returns. Phase 2 holds no key and never decrypts, so what is
    // asserted here is the envelope the Phase 3 crypto will be handed.
    const input = hex(
      "5a 00 2a 00 7f 7f 7c 01 01 7d 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "7e 10 9e 40 e1 ea 15 f6 50 80 8c 45 19 d5 2a bb 29 b8 d5 24",
    );
    const frame = ok(decodeFrames(input))[0];
    assert.equal(frame.serviceId, 0x7f);
    assert.equal(frame.commandId, 0x7f);
    assert.equal(frame.encryptedEnvelope, true);
    assert.deepEqual(frame.tlv?.getBytes(0x7c), bytes(0x01));
    assert.deepEqual(frame.tlv?.getBytes(0x7d), new Uint8Array(16));
    assert.equal(frame.tlv?.getBytes(0x7e).length, 16);
    assert.equal(entriesOf(frame.tlv).length, 3);
    // Re-serialising what arrived is byte-identical, so nothing is lost on the way to Phase 3.
    assert.deepEqual(frame.tlv?.serialize(), hex(
      "7c 01 01 7d 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "7e 10 9e 40 e1 ea 15 f6 50 80 8c 45 19 d5 2a bb 29 b8",
    ));
  });

  test("testKnownEncryptedPacketParse: service 0x0B command 0x01 carries the same envelope", () => {
    // TestHuaweiPacket:70-86 also asserts a decrypted TLV {0x01: false}; that needs Phase 3.
    const input = hex(
      "5a 00 2a 00 0b 01 7c 01 01 7d 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "7e 10 28 00 99 6f 2a cb 62 3a e6 54 28 54 f8 ab 54 83 f4 f4",
    );
    const frame = ok(decodeFrames(input))[0];
    assert.equal(frame.serviceId, 0x0b);
    assert.equal(frame.commandId, 0x01);
    assert.equal(frame.encryptedEnvelope, true);
    assert.equal(frame.tlv?.getBoolean(0x7c), true);
    assert.equal(frame.tlv?.getBytes(0x7e).length, 16);
  });

  test("a frame with a surplus behind it reports the bytes it consumed and hands back the rest", () => {
    const first = hex("5a 00 07 00 7f 7f 01 02 03 04 40 b6");
    const step = ok(decodeOneFrame(first));
    assert.equal(step.kind, "complete");
    assert.equal(step.kind === "complete" ? step.consumed : 0, first.length);

    const two = ok(decodeOneFrame(new Uint8Array([...first, ...first])));
    assert.equal(two.kind, "complete");
    assert.equal(two.kind === "complete" ? two.consumed : 0, first.length);
  });
});

describe("frame — TestHuaweiPacket serialise vectors, byte for byte", () => {
  const unslicedTlv = (): HuaweiTlv => new HuaweiTlv().putInt(0x03, 0x05060708);
  const slicedTlv = (): HuaweiTlv =>
    new HuaweiTlv().putInt(0x01, 0x00).putInt(0x02, 0x00).putInt(0x03, 0x00).putInt(0x04, 0x00);

  test("testUnencryptedUnslicedSerialize: 5a 00 09 00 01 02 03 04 05 06 07 08 A4 F0", () => {
    const frames = ok(
      encodeFrame({ serviceId: 0x01, commandId: 0x02, tlv: unslicedTlv(), sliced: false, isEncrypted: false }),
    );
    assert.equal(frames.length, 1);
    assert.deepEqual(frames[0], hex("5a 00 09 00 01 02 03 04 05 06 07 08 a4 f0"));
  });

  test("testUnencryptedSlicedSerialize: three 16-byte frames, with their exact CRCs", () => {
    const frames = ok(
      encodeFrame({
        serviceId: 0x01,
        commandId: 0x02,
        tlv: slicedTlv(),
        sliced: true,
        sliceSize: 0x10,
        isEncrypted: false,
      }),
    );
    assert.equal(frames.length, 3);
    assert.deepEqual(frames[0], hex("5a 00 0b 01 00 01 02 01 04 00 00 00 00 02 cc 98"));
    assert.deepEqual(frames[1], hex("5a 00 0b 02 01 04 00 00 00 00 03 04 00 00 fa d3"));
    assert.deepEqual(frames[2], hex("5a 00 0a 03 02 00 00 04 04 00 00 00 00 37 ca"));
  });

  test("a payload that fits one slice is sent unsliced, as upstream decides", () => {
    const frames = ok(
      encodeFrame({
        serviceId: 0x01,
        commandId: 0x02,
        tlv: unslicedTlv(),
        sliced: true,
        sliceSize: 0xf4,
        isEncrypted: false,
      }),
    );
    assert.equal(frames.length, 1);
    assert.deepEqual(frames[0], hex("5a 00 09 00 01 02 03 04 05 06 07 08 a4 f0"));
  });

  test("testEncryptedUnslicedSerialize needs the Phase 3 cipher, so it is refused, not guessed", () => {
    // TestHuaweiPacket:220-239 expects a frame whose TLV is the 7C/7D/7E envelope with a specific
    // ciphertext. Producing those bytes means porting HuaweiCrypto and holding a key: Phase 3.
    const refused = encodeFrame({
      serviceId: 0x01,
      commandId: 0x02,
      tlv: unslicedTlv(),
      sliced: false,
      isEncrypted: true,
      transactionsCrypted: true,
    });
    assert.equal(errorCode(refused), "unsupported");
    if (refused.ok) return;
    assert.match(refused.error.message, /Phase 3/);
  });

  test("before a key exists upstream sends the same bytes in the clear, and so does this", () => {
    // Upstream encrypts only when the packet wants it *and* the transaction is crypted
    // (HuaweiPacket.java:942-950); during the handshake it is not, so the plaintext frame is the
    // reference output. The default here is transactionsCrypted=false for exactly that reason.
    const plaintext = ok(
      encodeFrame({ serviceId: 0x01, commandId: 0x02, tlv: unslicedTlv(), sliced: false, isEncrypted: true }),
    );
    assert.deepEqual(plaintext[0], hex("5a 00 09 00 01 02 03 04 05 06 07 08 a4 f0"));
  });

  test("encode -> decode round-trips an unsliced frame exactly", () => {
    const tlv = new HuaweiTlv().putString(0x03, "BCS phase 2").putEmpty(0x09).putBoolean(0x0a, true);
    const frames = ok(encodeFrame({ serviceId: 0x1a, commandId: 0x05, tlv, sliced: false }));
    const frame = ok(decodeFrames(frames[0]))[0];
    assert.equal(frame.serviceId, 0x1a);
    assert.equal(frame.commandId, 0x05);
    assert.deepEqual(entriesOf(frame.tlv), entriesOf(tlv));
    assert.deepEqual(frame.tlv?.serialize(), tlv.serialize());
  });

  test("encode -> decode round-trips a sliced frame, reassembled across the slices", () => {
    const tlv = new HuaweiTlv();
    for (let i = 0; i < 12; i += 1) tlv.putInt(i + 1, i);
    const frames = ok(
      encodeFrame({ serviceId: 0x01, commandId: 0x03, tlv, sliced: true, sliceSize: 0x20, isEncrypted: false }),
    );
    assert.ok(frames.length > 1, "this payload must need more than one slice");
    assert.equal(frames[0][3], 0x01); // first
    assert.equal(frames[frames.length - 1][3], 0x03); // last
    const frame = ok(decodeFrames(Uint8Array.from(frames.flatMap((f) => [...f]))))[0];
    assert.equal(frame.serviceId, 0x01);
    assert.equal(frame.commandId, 0x03);
    assert.equal(frame.sliceCount, frames.length);
    assert.equal(frame.sliceType, 0x03);
    assert.deepEqual(frame.sliceFlags, frames.map((_, i) => i));
    assert.deepEqual(entriesOf(frame.tlv), entriesOf(tlv));
  });

  test("serializeUnsliced and serializeSliced agree with encodeFrame", () => {
    const payload = new HuaweiTlv().putInt(0x03, 0x05060708).serialize();
    assert.deepEqual(serializeUnsliced(0x01, 0x02, payload), hex("5a 00 09 00 01 02 03 04 05 06 07 08 a4 f0"));
    const one = ok(serializeSliced(0x01, 0x02, payload, 0x10));
    assert.equal(one.length, 1);
    assert.deepEqual(one[0], hex("5a 00 09 00 01 02 03 04 05 06 07 08 a4 f0"));
  });
});

describe("frame — bad input is a typed error, never a throw", () => {
  const valid = hex("5a 00 07 00 7f 7f 01 02 03 04 40 b6");

  test("a wrong first byte is bad-magic", () => {
    const wrong = new Uint8Array(valid);
    wrong[0] = 0x5b;
    assert.equal(errorCode(decodeFrames(wrong)), "bad-magic");
    // Upstream checks the magic before anything else, so a single wrong byte is a magic error.
    assert.equal(errorCode(decodeOneFrame(bytes(0x00))), "bad-magic");
    assert.equal(errorCode(decodeOneFrame(bytes(0x5b, 0x00, 0x07))), "bad-magic");
  });

  test("a lone 0x5A waits for more bytes instead of failing", () => {
    const step = ok(decodeOneFrame(bytes(0x5a)));
    assert.equal(step.kind, "incomplete");
    assert.equal(step.kind === "incomplete" ? step.needed : 0, 2);
  });

  test("a length the frame cannot cover is incomplete, and truncated once the stream ends", () => {
    const partial = valid.subarray(0, 6);
    const step = ok(decodeOneFrame(partial));
    assert.equal(step.kind, "incomplete");
    assert.equal(step.kind === "incomplete" ? step.needed : 0, valid.length - partial.length);
    assert.equal(errorCode(decodeFrames(partial)), "truncated");
  });

  test("a flipped byte is bad-crc, at the end and in the middle", () => {
    const lastByte = new Uint8Array(valid);
    lastByte[lastByte.length - 1] ^= 0x01;
    assert.equal(errorCode(decodeFrames(lastByte)), "bad-crc");

    const middle = new Uint8Array(valid);
    middle[6] ^= 0x01;
    assert.equal(errorCode(decodeFrames(middle)), "bad-crc");
  });

  test("a negative length field is bad-length, the upstream LengthMismatch case", () => {
    // `getShort()` is signed, so 0x8000 and up are negative lengths (HuaweiPacket.java:351-355).
    assert.equal(errorCode(decodeOneFrame(hex("5a 80 00 00"))), "bad-length");
    assert.equal(errorCode(decodeOneFrame(hex("5a ff ff 00 00 00 00 00"))), "bad-length");
  });

  test("a frame too short to hold the two id bytes is bad-length", () => {
    // Upstream reads newPayload[0]/[1] here and throws ArrayIndexOutOfBoundsException (:404-405).
    const head = bytes(0x5a, 0x00, 0x02, 0x00, 0x41);
    const crc = frameCrc16(head);
    const frame = Uint8Array.from([...head, (crc >> 8) & 0xff, crc & 0xff]);
    assert.equal(errorCode(decodeFrames(frame)), "bad-length");
  });

  test("a length of zero is bad-length too, not an empty frame", () => {
    const head = bytes(0x5a, 0x00, 0x00);
    const crc = frameCrc16(head);
    const frame = Uint8Array.from([...head, (crc >> 8) & 0xff, crc & 0xff]);
    assert.equal(errorCode(decodeFrames(frame)), "bad-length");
  });

  test("asking for two payloads at once, or an impossible slice size, is bad-argument", () => {
    assert.equal(
      errorCode(
        encodeFrame({
          serviceId: 0x01,
          commandId: 0x01,
          tlv: new HuaweiTlv().putEmpty(0x01),
          rawPayload: bytes(0x01),
        }),
      ),
      "bad-argument",
    );
    assert.equal(
      errorCode(serializeSliced(0x01, 0x01, new Uint8Array(64), 7)),
      "bad-argument",
    );
  });
});

describe("frame — the four packets whose payload is not a TLV", () => {
  test("every (service, command) pair upstream lists keeps its raw payload", () => {
    for (const [serviceId, commandId] of NON_TLV_PACKETS) {
      const rawPayload = bytes(0xde, 0xad);
      const frames = ok(
        encodeFrame({ serviceId, commandId, rawPayload, sliced: false, isEncrypted: false }),
      );
      const frame = ok(decodeFrames(frames[0]))[0];
      assert.equal(frame.serviceId, serviceId);
      assert.equal(frame.commandId, commandId);
      assert.equal(frame.tlv, null, `0x${serviceId.toString(16)}/0x${commandId.toString(16)} has no TLV`);
      assert.deepEqual(frame.payload, Uint8Array.from([serviceId, commandId, 0xde, 0xad]));
      assert.equal(frame.encryptedEnvelope, false);
    }
  });

  test("a packet that is not one of those four is parsed as TLV, so a bad one is reported", () => {
    const frames = ok(
      encodeFrame({ serviceId: 0x7f, commandId: 0x7f, rawPayload: bytes(0x01), sliced: false }),
    );
    assert.equal(errorCode(decodeFrames(frames[0])), "bad-tlv");
  });
});

describe("frame — garbage never throws", () => {
  const known = new Set(["bad-magic", "bad-length", "bad-crc", "truncated", "bad-tlv", "bad-value", "missing-tag", "bad-argument", "unsupported"]);

  test("500 random buffers each return a value or a typed error", () => {
    let seed = 0x1234abcd;
    const next = (): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed & 0xff;
    };
    for (let round = 0; round < 500; round += 1) {
      const length = next() % 48;
      const garbage = Uint8Array.from({ length }, next);
      const step = decodeOneFrame(garbage);
      if (!step.ok) {
        assert.equal(step.error.name, "HuaweiCodecError");
        assert.ok(known.has(step.error.code), `unexpected code ${step.error.code}`);
      }
      const frames = decodeFrames(garbage);
      if (!frames.ok) {
        assert.ok(known.has(frames.error.code), `unexpected code ${frames.error.code}`);
      }
    }
  });

  test("a stream of 0x5A bytes is either incomplete or a typed error, never a throw", () => {
    for (let length = 0; length < 40; length += 1) {
      const flood = new Uint8Array(length).fill(0x5a);
      const step = decodeOneFrame(flood);
      assert.ok(step.ok || known.has(step.error.code), `length ${length}`);
    }
  });
});