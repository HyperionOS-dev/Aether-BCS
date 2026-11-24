// BCS helper — Phase 2 (Huawei packet codec): the frame — magic, length, slice bytes, service and
// command ids, TLV payload, CRC16. Pure code: it takes bytes and returns objects and back. No
// socket, no process, no timer, no I/O, no key material, nothing sent to the watch.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Ported from Gadgetbridge, app/src/main/java/nodomain/freeyourgadget/gadgetbridge/devices/huawei/HuaweiPacket.java
// at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7 (GitHub mirror, frozen 2024-12-22):
//   PACKET_MINIMAL_SIZE                      line 246
//   parseData(byte[])                        lines 321-421   (frame layout, CRC, slice handling)
//   serializeUnsliced(byte[])                lines 828-847
//   serializeSliced(byte[])                  lines 767-826
//   the four non-TLV (service, command) pairs lines 408-417
//   checksum: CheckSums.getCRC16(seq, 0x0000)  lines 380, :819, :841 -> ./crc16.ts
// The magic byte and the slice defaults are in ./constants.ts. Gadgetbridge's own TestHuaweiPacket
// vectors are ported in test/huaweiFrame.test.ts.
//
// The wire layout, unsliced (all big-endian, as java.nio.ByteBuffer defaults):
//
//   0      magic 0x5A
//   1-2    length = (2 + tlvLength) + 1, i.e. payload + 1          HuaweiPacket.java:836
//   3      slice byte, 0x00 for unsliced                            :837
//   4      service id, 5 command id, then the TLV bytes             :838-840
//   n-2,n-1 CRC16 over bytes 0..n-3, seeded 0x0000                  :841-844
//
// Sliced frames use the same header with a non-zero slice byte: 0x01 first, 0x02 middle, 0x03 last,
// and one extra "flag" byte (a counter from 0) at index 4. Only the first slice carries the service
// and command ids (HuaweiPacket.java:799-804). Total frame length is length + 5 in both cases,
// which is the check a reader can make before it has parsed anything (upstream keeps any surplus
// bytes as `left`, :375).
//
// Deliberate divergences (three):
//  1. Every failure is a typed error, never a throw: a bad magic, a negative/impossible length, a
//     CRC mismatch, or a buffer that stops inside the frame.
//  2. A frame whose payload cannot even hold the two id bytes is "bad-length" here. Upstream reads
//     `newPayload[0]`/`[1]` and throws ArrayIndexOutOfBoundsException (:404-405).
//  3. Encryption is refused, not attempted: upstream encrypts the TLV whenever the packet wants it
//     and the transaction is crypted (:942-950). This phase holds no key, so asking for that is an
//     "unsupported" error naming Phase 3, while the default is the plaintext path upstream uses
//     before a key exists — byte-identical output for the handshake requests this phase can build.

import { isNonTlvPacket, CRYPTO_TAGS, DEFAULT_SLICE_SIZE, HUAWEI_MAGIC, PACKET_MINIMAL_SIZE } from "./constants.ts";
import { codecFail, codecOk, type CodecResult } from "./errors.ts";
import { frameCrc16 } from "./crc16.ts";
import { HuaweiTlv } from "./tlv.ts";

/** A complete, reassembled packet. */
export interface HuaweiFrame {
  serviceId: number;
  commandId: number;
  /**
   * The payload's TLVs, or null for the four (service, command) pairs whose payload is not a TLV
   * (HuaweiPacket.java:408-417). A non-null TLV here is *not* decrypted: an encrypted transaction
   * arrives as the 0x7C/0x7D/0x7E envelope and is reported, not opened.
   */
  tlv: HuaweiTlv | null;
  /** The bytes the TLVs were parsed from: service id + command id + TLV. */
  payload: Uint8Array;
  /** True when the payload is the encrypted-transaction envelope (tag 0x7C set to 1). No key here. */
  encryptedEnvelope: boolean;
  /** Slice byte of the frame that completed it: 0 unsliced, 1 first, 2 middle, 3 last. */
  sliceType: number;
  /** The "flag" byte of every slice that made up this frame, in arrival order. */
  sliceFlags: number[];
  /** How many slice frames this packet arrived in (1 when unsliced). */
  sliceCount: number;
}

/** One slice of a sliced packet, as it arrived. */
export interface FrameSlice {
  sliceType: 1 | 2 | 3;
  flag: number;
  /** This slice's part of the payload. The first slice starts with the two id bytes. */
  content: Uint8Array;
}

/**
 * The result of reading one frame from the front of a buffer. "incomplete" is not a failure: the
 * stream simply needs more bytes, which is the normal case in the middle of a read.
 */
export type FrameStep =
  | { kind: "complete"; frame: HuaweiFrame; consumed: number }
  | { kind: "slice"; slice: FrameSlice; consumed: number }
  | { kind: "incomplete"; needed: number };

function hex4(value: number): string {
  return (value & 0xffff).toString(16).padStart(4, "0");
}

/**
 * Turn a frame payload (service id + command id + TLV, or raw bytes for the four non-TLV pairs)
 * into a frame. Shared by the single-frame decoder and by the slice assembler in ./stream.ts,
 * because upstream does exactly the same thing in both paths (HuaweiPacket.java:404-420).
 */
export function frameFromPayload(
  content: Uint8Array,
  sliceType: number,
  sliceFlags: readonly number[],
  sliceCount = 1,
): CodecResult<HuaweiFrame> {
  if (content.length < 2) {
    return codecFail(
      "bad-length",
      `frame payload is ${content.length} bytes: too few for a service and command id`,
      4,
    );
  }
  const serviceId = content[0];
  const commandId = content[1];
  const frame: HuaweiFrame = {
    serviceId,
    commandId,
    tlv: null,
    payload: content,
    encryptedEnvelope: false,
    sliceType,
    sliceFlags: [...sliceFlags],
    sliceCount,
  };
  if (isNonTlvPacket(serviceId, commandId)) {
    return codecOk(frame); // upstream :408-417 keeps the raw payload and parses no TLV
  }
  const tlv = HuaweiTlv.from(content.subarray(2));
  if (!tlv.ok) return { ok: false, error: tlv.error };
  frame.tlv = tlv.value;
  const encryptionFlag = tlv.value.tryGetBoolean(CRYPTO_TAGS.encryption);
  frame.encryptedEnvelope = encryptionFlag.ok && encryptionFlag.value === true;
  return codecOk(frame);
}

/**
 * Read one frame from the front of `bytes`: an unsliced frame, one slice of a sliced frame, or a
 * report of how many bytes are still missing. Nothing is buffered here — see ./stream.ts for the
 * reassembly that survives split and merged reads.
 */
export function decodeOneFrame(bytes: Uint8Array): CodecResult<FrameStep> {
  // Upstream throws LengthMismatchException on an empty merged buffer (:331-336); Gadgetbridge's
  // TestHuaweiPacket.testEmptyPacketParse asserts that behaviour, so it is a typed error here.
  if (bytes.length < 1) {
    return codecFail("bad-length", "packet length mismatch: 0 < 1");
  }
  // Upstream checks the magic before anything else (:338-344).
  if (bytes[0] !== HUAWEI_MAGIC) {
    return codecFail("bad-magic", `magic mismatch: 0x${bytes[0].toString(16)} != 0x5a`, 0);
  }
  // Shorter than magic + length: a partial read, kept until more bytes arrive (:346-349).
  if (bytes.length < PACKET_MINIMAL_SIZE) {
    return codecOk({ kind: "incomplete", needed: PACKET_MINIMAL_SIZE - bytes.length });
  }
  const unsigned = (bytes[1] << 8) | bytes[2];
  const length = unsigned > 0x7fff ? unsigned - 0x10000 : unsigned; // upstream getShort() is signed
  if (length < 0) {
    return codecFail("bad-length", `expected length mismatch: ${length}`, 1);
  }
  // Total frame bytes: magic + length + slice byte (+ flag byte) + content + two CRC bytes.
  const total = length + 5;
  if (bytes.length < total) {
    return codecOk({ kind: "incomplete", needed: total - bytes.length });
  }
  const expectedCrc = (bytes[length + 3] << 8) | bytes[length + 4];
  const actualCrc = frameCrc16(bytes.subarray(0, length + 3));
  if (actualCrc !== expectedCrc) {
    return codecFail(
      "bad-crc",
      `checksum mismatch: 0x${hex4(actualCrc)} != 0x${hex4(expectedCrc)}`,
      length + 3,
    );
  }
  const sliceType = bytes[3];
  if (sliceType === 1 || sliceType === 2 || sliceType === 3) {
    if (length < 2) {
      // Upstream allocates new byte[length - 2] here and throws NegativeArraySizeException.
      return codecFail("bad-length", `sliced frame with length ${length} has no room for its flag byte`, 3);
    }
    const content = bytes.slice(5, 3 + length);
    return codecOk({
      kind: "slice",
      slice: { sliceType, flag: bytes[4], content },
      consumed: total,
    });
  }
  const content = bytes.slice(4, 3 + length);
  const frame = frameFromPayload(content, sliceType, []);
  if (!frame.ok) return frame;
  return codecOk({ kind: "complete", frame: frame.value, consumed: total });
}

/** What the callers must supply to build a frame. */
export interface EncodeFrameOptions {
  serviceId: number;
  commandId: number;
  /** The payload TLVs. Mutually exclusive with `rawPayload`. */
  tlv?: HuaweiTlv | null;
  /** Raw payload for the four non-TLV packets (HuaweiPacket.java:408-417). */
  rawPayload?: Uint8Array | null;
  /** Upstream default: sliced (HuaweiPacket.java:262). Only matters above one slice size. */
  sliced?: boolean;
  /** Negotiated slice size; upstream's default is 0xF4 (HuaweiPacket.java:64). */
  sliceSize?: number;
  /** Upstream's per-packet "should this be encrypted" flag, default true (HuaweiPacket.java:260). */
  isEncrypted?: boolean;
  /**
   * Upstream's `areTransactionsCrypted()` — true only once a secret key exists
   * (HuaweiPacket.java:942-950). This phase holds no key, so it defaults to false and produces the
   * plaintext frame upstream sends during the handshake. Setting it true is refused, not ignored.
   */
  transactionsCrypted?: boolean;
}

/** Frame an unsliced payload: encoder half of HuaweiPacket.serializeUnsliced (lines 828-847). */
export function serializeUnsliced(
  serviceId: number,
  commandId: number,
  payload: Uint8Array,
): Uint8Array {
  const bodyLength = 2 + payload.length; // service id + command id + payload
  const frame = new Uint8Array(4 + bodyLength + 2);
  frame[0] = HUAWEI_MAGIC;
  frame[1] = ((bodyLength + 1) >>> 8) & 0xff;
  frame[2] = (bodyLength + 1) & 0xff;
  frame[3] = 0x00; // not sliced
  frame[4] = serviceId & 0xff;
  frame[5] = commandId & 0xff;
  frame.set(payload, 6);
  const crc = frameCrc16(frame.subarray(0, frame.length - 2));
  frame[frame.length - 2] = (crc >>> 8) & 0xff;
  frame[frame.length - 1] = crc & 0xff;
  return frame;
}

/**
 * Frame a payload, slicing it when it does not fit: encoder half of
 * HuaweiPacket.serializeSliced (lines 767-826). One slice means an unsliced frame, as upstream
 * decides at line 775-776.
 */
export function serializeSliced(
  serviceId: number,
  commandId: number,
  payload: Uint8Array,
  sliceSize: number,
): CodecResult<Uint8Array[]> {
  const headerLength = 5; // magic + short length + slice byte + flag byte
  const footerLength = 2; // CRC16
  const maxBodySize = sliceSize - headerLength - footerLength;
  if (maxBodySize < 1) {
    return codecFail(
      "bad-argument",
      `slice size ${sliceSize} leaves no room for payload (needs more than ${headerLength + footerLength})`,
    );
  }
  const packetCount = Math.ceil((payload.length + 2) / maxBodySize);
  if (packetCount <= 1) return codecOk([serializeUnsliced(serviceId, commandId, payload)]);

  const frames: Uint8Array[] = [];
  let at = 0;
  let slice = 0x01;
  for (let i = 0; i < packetCount; i += 1) {
    const remaining = payload.length - at;
    const packetSize = Math.min(sliceSize, remaining + headerLength + footerLength);
    const isLast = i === packetCount - 1;
    const sliceByte = isLast ? 0x03 : slice;
    const frame = new Uint8Array(packetSize);
    frame[0] = HUAWEI_MAGIC;
    frame[1] = ((packetSize - headerLength) >>> 8) & 0xff;
    frame[2] = (packetSize - headerLength) & 0xff;
    frame[3] = sliceByte;
    frame[4] = i & 0xff; // upstream's flag counter, incremented per slice (line 797)
    let cursor = 5;
    let contentSize = packetSize - headerLength - footerLength;
    if (sliceByte === 0x01) {
      frame[5] = serviceId & 0xff;
      frame[6] = commandId & 0xff;
      cursor = 7;
      contentSize -= 2; // the two id bytes live in the first slice (lines 799-804)
      slice = 0x02;
    }
    frame.set(payload.subarray(at, at + contentSize), cursor);
    at += contentSize;
    const written = cursor + contentSize;
    if (written !== packetSize - footerLength) {
      return codecFail("bad-argument", `slice ${i} would be ${written} bytes, not ${packetSize - footerLength}`);
    }
    const crc = frameCrc16(frame.subarray(0, packetSize - footerLength));
    frame[packetSize - 2] = (crc >>> 8) & 0xff;
    frame[packetSize - 1] = crc & 0xff;
    frames.push(frame);
  }
  return codecOk(frames);
}

/** Encode a packet: HuaweiPacket.serialize (lines 934-960) without the crypto step. */
export function encodeFrame(options: EncodeFrameOptions): CodecResult<Uint8Array[]> {
  const isEncrypted = options.isEncrypted ?? true;
  const transactionsCrypted = options.transactionsCrypted ?? false;
  if (isEncrypted && transactionsCrypted) {
    return codecFail(
      "unsupported",
      "encrypted transactions need the Phase 3 cipher and a secret key; Phase 2 encodes plaintext only",
    );
  }
  if (options.rawPayload != null && options.tlv != null) {
    return codecFail("bad-argument", "pass either a TLV or a raw payload, not both");
  }
  const payload =
    options.rawPayload ?? (options.tlv == null ? new Uint8Array(0) : options.tlv.serialize());
  const serviceId = options.serviceId & 0xff;
  const commandId = options.commandId & 0xff;
  const sliced = options.sliced ?? true;
  const sliceSize = options.sliceSize ?? DEFAULT_SLICE_SIZE;
  if (!sliced) return codecOk([serializeUnsliced(serviceId, commandId, payload)]);
  return serializeSliced(serviceId, commandId, payload, sliceSize);
}
