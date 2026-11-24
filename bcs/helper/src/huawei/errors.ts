// BCS helper — Phase 2 (Huawei packet codec): typed codec errors. Pure code: no socket, no
// process, no timer, no I/O, no key material, and nothing is ever sent to the watch.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Gadgetbridge throws from every parse method (HuaweiPacket.ParseException and five subclasses,
// HuaweiPacket.java:185-244). A codec fed a live stream will meet garbage, so this port keeps the
// upstream error *taxonomy* but changes the delivery: every entry point that takes bytes returns
// a result union instead of throwing, and the codec never lets a JS TypeError escape. Errors
// still carry a stable `code` and are still Error objects, matching bcsError() in ../types.ts,
// so callers switch on the code and not on English text.

/** Every way the codec can refuse input, mapped from the upstream exception where one exists. */
export type HuaweiCodecErrorCode =
  /** Byte 0 is not 0x5A (upstream: MagicMismatchException, HuaweiPacket.java:340-344). */
  | "bad-magic"
  /** The length field is impossible: negative, or below the minimum a frame can carry. */
  | "bad-length"
  /** CRC16 does not match the bytes it covers (upstream: ChecksumIncorrectException, :381-386). */
  | "bad-crc"
  /** The buffer ends inside a frame or TLV. Mid-stream this means "wait"; at end(): "truncated". */
  | "truncated"
  /** TLV structure is impossible: a value or VarInt length runs past the end of the buffer. */
  | "bad-tlv"
  /** A tag was asked for that this TLV does not carry (MissingTagException, :213-217). */
  | "missing-tag"
  /** A typed getter met a value of the wrong size for that type. Upstream throws an unchecked
   *  BufferUnderflowException here; this port returns this code instead. */
  | "bad-value"
  /** The caller asked for something that cannot be encoded: two payloads at once, or a slice size
   *  with no room for payload. This code has no upstream counterpart — upstream would throw. */
  | "bad-argument"
  /** Outside the Phase 2 boundary: encrypted transactions (Phase 3) and write-type commands. */
  | "unsupported";

/** A codec error: an Error carrying a stable code, the byte offset (when known) and a hint. */
export interface HuaweiCodecError extends Error {
  code: HuaweiCodecErrorCode;
  /** Byte offset the decoder had reached, or null when the error is not positional. */
  offset: number | null;
  /** Short machine-readable hint, e.g. the tag number. Never payload bytes. */
  detail: string | null;
}

export function codecError(
  code: HuaweiCodecErrorCode,
  message: string,
  offset: number | null = null,
  detail: string | null = null,
): HuaweiCodecError {
  const err = new Error(message) as HuaweiCodecError;
  err.name = "HuaweiCodecError";
  err.code = code;
  err.offset = offset;
  err.detail = detail;
  return err;
}

export function isHuaweiCodecError(value: unknown): value is HuaweiCodecError {
  return value instanceof Error && typeof (value as HuaweiCodecError).code === "string"
    && typeof (value as HuaweiCodecError).offset !== "undefined";
}

/** What a byte-in entry point returns: a value, or a typed error. Never a throw. */
export type CodecResult<T> = { ok: true; value: T } | { ok: false; error: HuaweiCodecError };

export function codecOk<T>(value: T): CodecResult<T> {
  return { ok: true, value };
}

export function codecFail<T>(
  code: HuaweiCodecErrorCode,
  message: string,
  offset: number | null = null,
  detail: string | null = null,
): CodecResult<T> {
  return { ok: false, error: codecError(code, message, offset, detail) };
}
