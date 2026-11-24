// BCS helper — Phase 2 (Huawei packet codec): the Huawei TLV (tag, VarInt length, value). Pure
// code: no socket, no I/O, no key material, nothing sent to the watch.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Ported from Gadgetbridge, app/src/main/java/nodomain/freeyourgadget/gadgetbridge/devices/huawei/HuaweiTLV.java
// at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7 (GitHub mirror, frozen 2024-12-22):
//   TLV inner class (tag/value/length/serialize/toString)  lines 47-87
//   HuaweiTLV.length()                                     lines 97-102
//   parse(byte[], int, int)                                lines 104-136
//   serialize()                                            lines 145-154
//   put() overloads                                        lines 156-206
//   getBytes/getByte/getBoolean/getInteger/...             lines 208-309
//   getAsInteger/getString/getObject/getObjects            lines 300-330
//   contains/remove/toString                               lines 332-380
// VarInt lives in ./varint.ts. Gadgetbridge's own TestHuaweiTLV vectors are ported in
// test/huaweiTlv.test.ts.
//
// Deliberate divergences (three), all forced by "never throw on garbage":
//  1. parse() returns a typed error where Java walks off the end of the array
//     (ArrayIndexOutOfBoundsException; see TestHuaweiTLV lines 261-266 and 283-288).
//  2. The typed getters return a typed error where Java throws an unchecked
//     BufferUnderflowException, e.g. getInteger() on a two-byte value.
//  3. The overload names are explicit (putByte/putInt/putShort/putString/putBytes/putTlv) instead of
//     one Java-style overload set, because a numeric value is ambiguous in TypeScript. Each method
//     maps 1:1 to an upstream overload and says so.
//
// The length encoding is the edge case the format turns on: a value length is a 7-bit VarInt, so
// 0..127 is one byte (00..7F) and 128 becomes 81 00. Serialising always writes the shortest form
// (VarInt.putVarIntValue), so a parse -> serialise round trip is byte-identical even if the sender
// chose a longer form than necessary.

import { codecError, codecFail, codecOk, type CodecResult } from "./errors.ts";
import { encodeVarInt, readVarInt, varIntSize } from "./varint.ts";

/** One TLV pair. `tag` is a byte kept as 0..255; `value` holds the raw value bytes. */
export interface TlvEntry {
  tag: number;
  value: Uint8Array;
}

/** True when two entries have the same tag and the same bytes (upstream: TLV.equals, :80-86). */
export function tlvEntryEquals(a: TlvEntry, b: TlvEntry): boolean {
  if (a.tag !== b.tag || a.value.length !== b.value.length) return false;
  for (let i = 0; i < a.value.length; i += 1) {
    if (a.value[i] !== b.value[i]) return false;
  }
  return true;
}

/** True when two entry lists are equal in order (upstream: HuaweiTLV.equals compares valueMap). */
export function tlvEntriesEqual(a: readonly TlvEntry[], b: readonly TlvEntry[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((entry, i) => tlvEntryEquals(entry, b[i]));
}

/** Uppercase hex: StringUtils.bytesToHex -> GB.hexdump, table "0123456789ABCDEF" (GB.java:368-382). */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out.toUpperCase();
}

/** Big-endian integer reader behind the typed getters. Null instead of reading past the end. */
export function readUnsignedBE(bytes: Uint8Array, size: number): bigint | null {
  if (bytes.length < size) return null;
  let value = 0n;
  for (let i = 0; i < size; i += 1) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}

/** A mutable TLV list with upstream's builder API. A tag may repeat; order is preserved. */
export class HuaweiTlv {
  readonly entries: TlvEntry[] = [];

  constructor(entries?: readonly TlvEntry[]) {
    if (entries) {
      this.entries.push(...entries.map((e) => ({ tag: e.tag & 0xff, value: Uint8Array.from(e.value) })));
    }
  }

  /** Total encoded length: sum of (1 tag byte + VarInt length + value). Upstream :97-102. */
  length(): number {
    let total = 0;
    for (const entry of this.entries) {
      total += 1 + varIntSize(entry.value.length) + entry.value.length;
    }
    return total;
  }

  /** Serialise to bytes. An empty TLV serialises to zero bytes, as upstream :145-149 does. */
  serialize(): Uint8Array {
    const out = new Uint8Array(this.length());
    let at = 0;
    for (const entry of this.entries) {
      out[at] = entry.tag & 0xff;
      at += 1;
      const size = encodeVarInt(entry.value.length);
      out.set(size, at);
      at += size.length;
      out.set(entry.value, at);
      at += entry.value.length;
    }
    return out;
  }

  /**
   * Parse a byte range into this TLV, appending to what it already holds (upstream :104-136 parses
   * into `this`). Returns this on success, so it can be chained.
   *
   * Upstream's "extra null byte at the end of something encrypted" rule is kept: a lone 0x00 tag
   * that is the very last byte is ignored rather than read as a tag with a missing length.
   */
  parse(buffer: Uint8Array, offset = 0, length = buffer.length - offset): CodecResult<this> {
    if (offset < 0 || length < 0 || offset + length > buffer.length) {
      return codecFail("bad-tlv", `TLV range ${offset}+${length} is outside a ${buffer.length}-byte buffer`, offset);
    }
    let parsed = 0;
    while (parsed < length) {
      const tag = buffer[offset + parsed];
      parsed += 1;
      if (parsed === length && tag === 0) break; // trailing null byte: ignore it
      const size = readVarInt(buffer, offset + parsed);
      if (!size.ok) {
        return codecFail("bad-tlv", `TLV tag 0x${tag.toString(16)} has no readable length`, size.error.offset);
      }
      parsed += size.value.size;
      const valueLength = size.value.value;
      if (parsed + valueLength > length) {
        return codecFail(
          "bad-tlv",
          `TLV tag 0x${tag.toString(16)} claims ${valueLength} value bytes with only ${length - parsed} left`,
          offset + parsed,
        );
      }
      this.entries.push({ tag, value: buffer.slice(offset + parsed, offset + parsed + valueLength) });
      parsed += valueLength;
    }
    return codecOk(this);
  }

  /** Parse a buffer into a fresh TLV (upstream: `new HuaweiTLV().parse(bytes)`). */
  static from(buffer: Uint8Array, offset = 0, length = buffer.length - offset): CodecResult<HuaweiTlv> {
    return new HuaweiTlv().parse(buffer, offset, length);
  }

  // ---- builder API: one method per upstream put() overload -------------------------------

  /** put(int tag): a tag with an empty value. Upstream :156-160. */
  putEmpty(tag: number): this {
    this.entries.push({ tag: tag & 0xff, value: new Uint8Array(0) });
    return this;
  }

  /** put(int tag, byte[] value): a null value adds nothing at all. Upstream :162-168. */
  putBytes(tag: number, value: Uint8Array | null | undefined): this {
    if (value == null) return this;
    this.entries.push({ tag: tag & 0xff, value: Uint8Array.from(value) });
    return this;
  }

  /** put(int tag, byte value). Upstream :170-172. */
  putByte(tag: number, value: number): this {
    return this.putBytes(tag, Uint8Array.of(value & 0xff));
  }

  /** put(int tag, boolean value): 1 or 0. Upstream :174-176. */
  putBoolean(tag: number, value: boolean): this {
    return this.putByte(tag, value ? 1 : 0);
  }

  /** put(int tag, int value): four bytes big-endian. Upstream :186-188. */
  putInt(tag: number, value: number): this {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setInt32(0, value | 0, false);
    return this.putBytes(tag, bytes);
  }

  /** put(int tag, short value): two bytes big-endian. Upstream :190-192. */
  putShort(tag: number, value: number): this {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setInt16(0, (value << 16) >> 16, false);
    return this.putBytes(tag, bytes);
  }

  /** put(int tag, Long value): eight bytes big-endian. Upstream :178-180. */
  putLong(tag: number, value: bigint | number): this {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigInt64(0, BigInt(value), false);
    return this.putBytes(tag, bytes);
  }

  /** put(int tag, Double value): eight bytes *little*-endian, as upstream :182-184 does. */
  putDouble(tag: number, value: number): this {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setFloat64(0, value, true);
    return this.putBytes(tag, bytes);
  }

  /** put(int tag, String value): UTF-8 bytes; a null string adds nothing. Upstream :194-199. */
  putString(tag: number, value: string | null | undefined): this {
    if (value == null) return this;
    return this.putBytes(tag, new TextEncoder().encode(value));
  }

  /** put(int tag, HuaweiTLV value): a nested TLV, serialised into the value. Upstream :201-206. */
  putTlv(tag: number, value: HuaweiTlv | null | undefined): this {
    if (value == null) return this;
    return this.putBytes(tag, value.serialize());
  }

  // ---- readers: upstream's API plus a non-throwing twin for each --------------------------

  /** The first entry with this tag, or a typed "missing-tag". Upstream getBytes :208-217. */
  tryGetBytes(tag: number): CodecResult<Uint8Array> {
    const wanted = tag & 0xff;
    for (const entry of this.entries) {
      if (entry.tag === wanted) return codecOk(entry.value);
    }
    const detail = `tag 0x${wanted.toString(16)}`;
    return codecFail("missing-tag", `this TLV carries no ${detail}`, null, detail);
  }

  /** Upstream's throwing form, kept because the ported vectors use it. The error is typed. */
  getBytes(tag: number): Uint8Array {
    const found = this.tryGetBytes(tag);
    if (!found.ok) throw found.error;
    return found.value;
  }

  /** getBytes(int tag, byte[] defaultValue). Upstream :219-225. */
  getBytesOrDefault(tag: number, defaultValue: Uint8Array): Uint8Array {
    const found = this.tryGetBytes(tag);
    return found.ok ? found.value : defaultValue;
  }

  /** getByte(int tag). Upstream :227-229 returns getBytes(tag)[0]. */
  tryGetByte(tag: number): CodecResult<number> {
    const found = this.tryGetBytes(tag);
    if (!found.ok) return found;
    if (found.value.length < 1) {
      return codecFail("bad-value", `tag 0x${(tag & 0xff).toString(16)} has an empty value, so no byte`, null, `tag 0x${(tag & 0xff).toString(16)}`);
    }
    return codecOk(found.value[0]);
  }

  getByte(tag: number): number {
    const found = this.tryGetByte(tag);
    if (!found.ok) throw found.error;
    return found.value;
  }

  /** getByte(int tag, Byte defaultValue). Upstream :231-237. */
  getByteOrDefault(tag: number, defaultValue: number): number {
    const found = this.tryGetByte(tag);
    return found.ok ? found.value : defaultValue;
  }

  /** getBoolean(int tag): the first value byte is exactly 1. Upstream :239-241. */
  tryGetBoolean(tag: number): CodecResult<boolean> {
    const found = this.tryGetByte(tag);
    if (!found.ok) return found;
    return codecOk(found.value === 1);
  }

  getBoolean(tag: number): boolean {
    const found = this.tryGetBoolean(tag);
    if (!found.ok) throw found.error;
    return found.value;
  }

  getBooleanOrDefault(tag: number, defaultValue: boolean): boolean {
    const found = this.tryGetBoolean(tag);
    return found.ok ? found.value : defaultValue;
  }

  /** getInteger(int tag): four bytes big-endian, signed 32-bit. Upstream :243-245. */
  tryGetInteger(tag: number): CodecResult<number> {
    const found = this.tryGetBytes(tag);
    if (!found.ok) return found;
    const raw = readUnsignedBE(found.value, 4);
    if (raw === null) {
      const detail = `tag 0x${(tag & 0xff).toString(16)}`;
      return codecFail("bad-value", `${detail} is ${found.value.length} bytes, too few for an int`, null, detail);
    }
    return codecOk(Number(BigInt.asIntN(32, raw)));
  }

  getInteger(tag: number): number {
    const found = this.tryGetInteger(tag);
    if (!found.ok) throw found.error;
    return found.value;
  }

  getIntegerOrDefault(tag: number, defaultValue: number): number {
    const found = this.tryGetInteger(tag);
    return found.ok ? found.value : defaultValue;
  }

  /** getShort(int tag): two bytes big-endian, signed. Upstream :255-257. */
  tryGetShort(tag: number): CodecResult<number> {
    const found = this.tryGetBytes(tag);
    if (!found.ok) return found;
    const raw = readUnsignedBE(found.value, 2);
    if (raw === null) {
      const detail = `tag 0x${(tag & 0xff).toString(16)}`;
      return codecFail("bad-value", `${detail} is ${found.value.length} bytes, too few for a short`, null, detail);
    }
    return codecOk(Number(BigInt.asIntN(16, raw)));
  }

  getShort(tag: number): number {
    const found = this.tryGetShort(tag);
    if (!found.ok) throw found.error;
    return found.value;
  }

  getShortOrDefault(tag: number, defaultValue: number): number {
    const found = this.tryGetShort(tag);
    return found.ok ? found.value : defaultValue;
  }

  /** getLong(int tag): eight bytes big-endian, signed. Upstream :266-268. */
  tryGetLong(tag: number): CodecResult<bigint> {
    const found = this.tryGetBytes(tag);
    if (!found.ok) return found;
    const raw = readUnsignedBE(found.value, 8);
    if (raw === null) {
      const detail = `tag 0x${(tag & 0xff).toString(16)}`;
      return codecFail("bad-value", `${detail} is ${found.value.length} bytes, too few for a long`, null, detail);
    }
    return codecOk(BigInt.asIntN(64, raw));
  }

  getLong(tag: number): bigint {
    const found = this.tryGetLong(tag);
    if (!found.ok) throw found.error;
    return found.value;
  }

  /**
   * getAsInteger(int tag): a one-byte value is read unsigned, a two-byte value unsigned, anything
   * else as a signed 32-bit int. Upstream :300-308. Upstream's else-branch reads four bytes even
   * from a three-byte value and throws BufferUnderflow; a short value is a typed error here.
   */
  tryGetAsInteger(tag: number): CodecResult<number> {
    const found = this.tryGetBytes(tag);
    if (!found.ok) return found;
    const detail = `tag 0x${(tag & 0xff).toString(16)}`;
    if (found.value.length === 1) return codecOk(found.value[0]);
    if (found.value.length === 2) return codecOk(found.value[0] * 256 + found.value[1]);
    const raw = readUnsignedBE(found.value, 4);
    if (raw === null) {
      return codecFail("bad-value", `${detail} is ${found.value.length} bytes, which is not 1, 2 or 4+`, null, detail);
    }
    return codecOk(Number(BigInt.asIntN(32, raw)));
  }

  getAsInteger(tag: number): number {
    const found = this.tryGetAsInteger(tag);
    if (!found.ok) throw found.error;
    return found.value;
  }

  /** getString(int tag): the value decoded as UTF-8. Upstream :310-312. */
  tryGetString(tag: number): CodecResult<string> {
    const found = this.tryGetBytes(tag);
    if (!found.ok) return found;
    return codecOk(new TextDecoder().decode(found.value));
  }

  getString(tag: number): string {
    const found = this.tryGetString(tag);
    if (!found.ok) throw found.error;
    return found.value;
  }

  /** getObject(int tag): the value parsed as a nested TLV. Upstream :314-317. */
  tryGetObject(tag: number): CodecResult<HuaweiTlv> {
    const found = this.tryGetBytes(tag);
    if (!found.ok) return found;
    const nested = HuaweiTlv.from(found.value);
    if (!nested.ok) return nested;
    return codecOk(nested.value);
  }

  getObject(tag: number): HuaweiTlv {
    const found = this.tryGetObject(tag);
    if (!found.ok) throw found.error;
    return found.value;
  }

  /** getObjects(int tag): every entry with that tag, each parsed as a nested TLV. Upstream :319-327. */
  tryGetObjects(tag: number): CodecResult<HuaweiTlv[]> {
    const wanted = tag & 0xff;
    const out: HuaweiTlv[] = [];
    for (const entry of this.entries) {
      if (entry.tag !== wanted) continue;
      const nested = HuaweiTlv.from(entry.value);
      if (!nested.ok) return nested;
      out.push(nested.value);
    }
    return codecOk(out);
  }

  getObjects(tag: number): HuaweiTlv[] {
    const found = this.tryGetObjects(tag);
    if (!found.ok) throw found.error;
    return found.value;
  }

  /** contains(int tag). Upstream :332-338. */
  contains(tag: number): boolean {
    return this.entries.some((entry) => entry.tag === (tag & 0xff));
  }

  /**
   * remove(int tag): removes the *last* entry with that tag and returns its value, or null when
   * there is none (upstream :344-353; TestHuaweiTLV :444-462 removes the same tag twice).
   */
  remove(tag: number): Uint8Array | null {
    const wanted = tag & 0xff;
    let index = -1;
    for (let i = 0; i < this.entries.length; i += 1) {
      if (this.entries[i].tag === wanted) index = i;
    }
    if (index < 0) return null;
    const [removed] = this.entries.splice(index, 1);
    return removed.value;
  }

  /**
   * Upstream :372-380: entries rendered as `{tag: <lowercase hex> - Value: <UPPERCASE hex>}`
   * separated by " - " ("Empty" when there are none). Gadgetbridge builds the same string by
   * appending "{...} - " per entry and trimming the last separator, which is identical.
   */
  toString(): string {
    if (this.entries.length === 0) return "Empty";
    return this.entries
      .map((entry) => `{tag: ${(entry.tag & 0xff).toString(16)} - Value: ${bytesToHex(entry.value)}}`)
      .join(" - ");
  }

  /** Upstream HuaweiTLV.equals compares the entry list only (:39-45). */
  equals(other: HuaweiTlv | null | undefined): boolean {
    return other instanceof HuaweiTlv && tlvEntriesEqual(this.entries, other.entries);
  }
}

