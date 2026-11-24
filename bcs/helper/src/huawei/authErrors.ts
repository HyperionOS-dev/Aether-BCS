// BCS helper — Phase 3 (trust/auth): the typed error taxonomy for the auth state machine. Pure code:
// no socket, no process, no timer, no I/O, and no key material — not even in `detail`.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// Original to this project: upstream throws (RequestCreationException, ResponseParseException,
// HuaweiCrypto.CryptoException and five HuaweiPacket.ParseException subclasses). A state machine fed
// a live link needs to *return* its failures, and it needs codes that say where it stopped, so the
// caller can report "stopped at HiChain step 2" without guessing.
//
// Hard rule enforced by construction: no code in this file, and no caller, may put key bytes,
// key hex or a key-derived value into `message` or `detail`. The test `authKeyLeak.test.ts` asserts
// that a fake key's hex/base64 never appears in any error string or log line the machine produces.

import { codecError } from "./errors.ts";

/** Every way the auth flow can stop. */
export type HuaweiAuthErrorCode =
  /** The device negotiated a path Phase 3 does not implement (e.g. the legacy digest auth). */
  | "auth-unsupported"
  /** A frame arrived that this state does not expect — out of order, replayed, or from nowhere. */
  | "auth-state"
  /** The reply was cut short (TLV or JSON ended early). */
  | "auth-truncated"
  /** The device answered with a non-zero errorCode, or a return code that is not success. */
  | "auth-refused"
  /** A MAC the device sent does not match the one we computed. Wrong key, or a tampered reply. */
  | "auth-mac-mismatch"
  /** The device's step-1 token does not match. Wrong key, almost always. */
  | "auth-token-mismatch"
  /** The link params / negotiation reply is missing a tag this flow requires. */
  | "auth-negotiation"
  /** A pin code is needed for this run and the caller did not supply one. */
  | "auth-pincode-missing"
  /** The key is the wrong shape (empty, not 16/32 bytes where that is required). */
  | "bad-key"
  /** A caller argument is wrong (bad hex, bad length, bad mode). */
  | "bad-argument"
  /** A buffer was too short for the structure it should hold. */
  | "bad-length"
  /** A cryptographic primitive failed (a bad GCM tag, a bad CBC padding). */
  | "crypto-failed";

export interface HuaweiAuthError extends Error {
  code: HuaweiAuthErrorCode;
  /** Which step of the flow produced it, when known. Never key material. */
  step: string | null;
  /** Short machine-readable hint — a tag number, a length, a step index. Never key material. */
  detail: string | null;
}

/**
 * Build a typed auth error. `step` and `detail` are for diagnostics and must never carry bytes taken
 * from the key; every call site in this phase passes a literal string or a number.
 */
export function authError(
  code: HuaweiAuthErrorCode,
  message: string,
  step: string | null = null,
  detail: string | null = null,
): HuaweiAuthError {
  const err = codecError(code as never, message, null, detail) as unknown as HuaweiAuthError;
  err.name = "HuaweiAuthError";
  err.step = step;
  return err;
}

export function isHuaweiAuthError(value: unknown): value is HuaweiAuthError {
  return value instanceof Error
    && typeof (value as HuaweiAuthError).code === "string"
    && typeof (value as HuaweiAuthError).step !== "undefined";
}