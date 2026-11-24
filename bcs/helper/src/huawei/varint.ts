// BCS helper — Phase 2 (Huawei packet codec): the 7-bit VarInt that encodes TLV lengths. Pure
// code: no socket, no I/O, no keys, nothing sent to the watch.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Ported from Gadgetbridge, app/src/main/java/nodomain/freeyourgadget/gadgetbridge/devices/huawei/HuaweiTLV.java,
// final class VarInt, lines 384-452, at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7
// (GitHub mirror, frozen 2024-12-22):
//   getVarIntSize(int)            lines 405-412
//   getVarIntValue(byte[], int)   lines 422-433
//   putVarIntValue(int)           lines 442-451
// Gadgetbridge's own TestVarInt vectors are ported in test/huaweiVarInt.test.ts.
//
// Deliberate divergence (one): the Java decode reads bytes without a bound and would throw
// ArrayIndexOutOfBoundsException on a truncated value. Here it returns a typed error, because the
// codec is fed live bytes. Java's int arithmetic also wraps silently past four bytes; this port
// stops at five bytes and reports the malformation, so a bad length cannot turn into a huge read.

import { codecFail, codecOk, type CodecResult } from "./errors.ts";

/** Longest VarInt Gadgetbridge's arithmetic can express in its 32-bit int: ceil(32 / 7) = 5. */
export const MAX_VARINT_BYTES = 5;

export interface VarIntValue {
  /** The decoded value, as an unsigned 32-bit integer. */
  value: number;
  /** How many bytes the encoded value occupies. */
  size: number;
}

/**
 * Encoding size of a value: `getVarIntSize`, one 7-bit group per byte, at least one byte.
 * The value is treated as unsigned 32-bit, exactly as Java's `>>>=` does.
 */
export function varIntSize(value: number): number {
  let v = value >>> 0;
  let result = 0;
  do {
    result += 1;
    v >>>= 7;
  } while (v !== 0);
  return result;
}

/**
 * Encode a value: `putVarIntValue`. All but the last byte carry the 0x80 continuation bit.
 * 0 -> [00], 17 -> [11], 0x80 -> [81, 00], 460 -> [83, 4C] (TestVarInt, lines 36-54).
 */
export function encodeVarInt(value: number): Uint8Array {
  const v0 = value >>> 0;
  const size = varIntSize(v0);
  const result = new Uint8Array(size);
  result[size - 1] = v0 & 0x7f;
  let v = v0;
  for (let offset = size - 2; offset >= 0; offset -= 1) {
    v >>>= 7;
    result[offset] = (v & 0x7f) | 0x80;
  }
  return result;
}

/**
 * Decode a value starting at `offset`: `getVarIntValue`. Returns "truncated" when the bytes run
 * out inside the value and "bad-tlv" when the continuation bit never clears within five bytes.
 */
export function readVarInt(src: Uint8Array, offset: number): CodecResult<VarIntValue> {
  if (offset < 0 || offset >= src.length) {
    return codecFail("truncated", `VarInt starts past the end of the buffer (offset ${offset})`, offset);
  }
  let result = 0;
  for (let n = 0; ; n += 1) {
    if (n >= MAX_VARINT_BYTES) {
      return codecFail(
        "bad-tlv",
        `VarInt is longer than ${MAX_VARINT_BYTES} bytes and never terminates`,
        offset,
      );
    }
    const at = offset + n;
    if (at >= src.length) {
      return codecFail("truncated", "VarInt ends before its last byte arrives", at);
    }
    const b = src[at];
    result = (result + (b & 0x7f)) | 0;
    if ((b & 0x80) === 0) {
      return codecOk({ value: result >>> 0, size: n + 1 });
    }
    result = result << 7; // Java: result <<= 7 (32-bit, wraps the same way)
  }
}
