// BCS helper — Phase 2 (Huawei packet codec): CRC16. Pure code: no socket, no I/O, no keys.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Ported from Gadgetbridge, app/src/main/java/nodomain/freeyourgadget/gadgetbridge/util/CheckSums.java
//   getCRC16(byte[] seq)          lines 59-61
//   getCRC16(byte[] seq, int crc) lines 63-73
// at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7 (GitHub mirror, frozen 2024-12-22).
// The frame code calls it with a seed of 0x0000 (HuaweiPacket.java:380, :819, :841); upstream's
// one-argument form seeds 0xFFFF and is kept here only for completeness.
//
// Which variant is it? Verified, not assumed: this loop is byte-identical to CRC-16/XMODEM
// (poly 0x1021, init 0x0000, MSB-first, no reflection, no final XOR). Evidence: it reproduces the
// CRC of every Gadgetbridge test frame (0x40B6, 0xA4F0, 0xCC98, 0xFAD3, 0x37CA) and returns the
// published XMODEM check value 0x31C3 for the ASCII bytes "123456789"; test/huaweiCrc16.test.ts
// re-checks both facts, including against an independent bit-by-bit implementation.
//
// This file is ours: the arithmetic was read line by line from the Java above, but the same loop
// is a standard CCITT-style CRC16. If you prefer a table-driven or bitwise version, replace it
// only if test/huaweiCrc16.test.ts still passes — the five test-frame vectors are authoritative.

/**
 * CRC16 as Gadgetbridge computes it. `crc` is the running/seed value; Java's int arithmetic is
 * 32-bit, so every intermediate is masked to 16 bits exactly where the Java does it.
 */
export function crc16(seq: Uint8Array, crc = 0xffff): number {
  let acc = crc & 0xffff;
  for (const b of seq) {
    acc = ((acc >>> 8) | (acc << 8)) & 0xffff;
    acc ^= b & 0xff; // byte to int, truncate sign
    acc ^= (acc & 0xff) >> 4;
    acc ^= (acc << 12) & 0xffff;
    acc ^= ((acc & 0xff) << 5) & 0xffff;
  }
  return acc & 0xffff;
}

/**
 * The frame's checksum: CRC16 over everything before the two checksum bytes, seeded 0x0000.
 * HuaweiPacket.java:380 (decode) and :841 (encode) both use this seed.
 */
export function frameCrc16(covered: Uint8Array): number {
  return crc16(covered, 0x0000);
}

/** A big-endian pair, which is how the frame writes its checksum (java.nio ByteBuffer.putShort). */
export function crc16Bytes(covered: Uint8Array, seed = 0x0000): Uint8Array {
  const value = crc16(covered, seed);
  return Uint8Array.of((value >>> 8) & 0xff, value & 0xff);
}
