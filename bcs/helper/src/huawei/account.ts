// BCS helper — Phase 3E (account support): the Huawei account ID, validated, and the frame upstream
// sends for it. Pure code: no socket, no I/O, no file, no timer, no logging. The value is passed in,
// encoded, and never put in an error `message` or `detail`.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// WHAT UPSTREAM SAYS, from Gadgetbridge at commit a0948ee1cbc2a870f91d313f8e37df5f524465f7:
//   * res/values/strings.xml:3366-3367 — "Huawei account used in pairing process. Setting it allows
//     to pair without factory reset."
//   * HuaweiSupportProvider.java:786-787 — `SendExtendedAccountRequest` is the second request of the
//     dynamic-services phase (`initializeDynamicServices`, :782-800), reached only after LinkParams
//     (:407), DeviceStatus (:445), SecurityNegotiation (:505), the pin code (:569) and the HiChain
//     auth/bind (:566, GetHiChainRequest.java:180-196) have all finished. Never before or during them.
//   * HuaweiCoordinator.java:585-591 — the 0x05 frame is gated on the watch advertising both
//     (0x1A, 0x05) and (0x1A, 0x06).
//   * packets/AccountRelated.java:23, :26, :53 — service 0x1A, command 0x01 (legacy, unused at this
//     commit) and command 0x05 (what Gadgetbridge queues).
//   * The value is only ever a TLV string under tag 0x01 (:63-64; :36-37 for the legacy command). It
//     is never hashed, never a PSK, never a session or return key: PREF_HUAWEI_ACCOUNT is read in
//     exactly two places, SendAccountRequest.java:42-44 and SendExtendedAccountRequest.java:47-49.
//   * Upstream validates neither length nor digits, and its own text field caps at 17
//     (res/xml/devicesettings_huawei_account.xml:6, still 17 on master). This helper accepts 17 to 19
//     digits and refuses everything else.
//
// THE SEND GATE — why this file never claims a frame is ready to send. `AccountRelated` sets no
// `isEncrypted` flag, so the packet keeps HuaweiPacket's default `true` (HuaweiPacket.java:260), and
// `serialize()` wraps the payload in the crypto envelope `{0x7C: 0x01, 0x7D: iv, 0x7E: ciphertext}`
// whenever `isEncrypted && areTransactionsCrypted()` (:934-950, condition at :942-944), keyed with
// `paramsProvider.getSecretKey()` (HuaweiTLV.java:349-361) — which after HiChain bind step 4 *is* the
// derived key (GetHiChainRequest.java:188-196). `transactionCrypted` defaults to true
// (HuaweiCoordinator.java:87), so this is the normal case, not an edge case. This helper's codec
// refuses encrypted transactions by design (`frame.ts`: "Phase 2 encodes plaintext only"), so
// `encodeAccountFrame()` returns a typed `unsupported` result unless the caller states that the link
// is not crypted. Nothing here guesses at the envelope, and nothing here sends anything.

import { ACCOUNT_RELATED } from "./constants.ts";
import { codecFail, codecOk, type CodecResult } from "./errors.ts";
import {
  encodeRequest,
  sendAccountRequest,
  sendExtendedAccountRequest,
  type HuaweiRequest,
} from "./requests.ts";

/** Shortest Huawei account this helper accepts. Upstream's own field stops at 17. */
export const ACCOUNT_ID_MIN_DIGITS = 17;
/** Longest Huawei account this helper accepts, per the task's 17–19 range. */
export const ACCOUNT_ID_MAX_DIGITS = 19;

/** Which of the two account commands upstream defines a frame for. */
export type AccountCommand = "send" | "send-extended";

/** The (service, command) pairs an account frame can use. Both are in ALLOWED_REQUEST_IDS. */
export const ACCOUNT_FRAME_PAIRS: readonly (readonly [number, number])[] = [
  [ACCOUNT_RELATED.serviceId, ACCOUNT_RELATED.sendAccountToDevice],
  [ACCOUNT_RELATED.serviceId, ACCOUNT_RELATED.sendExtendedAccountToDevice],
];

/** True when `text` is an account this helper accepts: digits only, 17 to 19 of them. */
export function isAccountId(text: string): boolean {
  const trimmed = text.trim();
  return new RegExp(`^[0-9]{${ACCOUNT_ID_MIN_DIGITS},${ACCOUNT_ID_MAX_DIGITS}}$`).test(trimmed);
}

/**
 * Validate a value read from anywhere. The value itself never appears in the result: only its
 * length and the kind of problem, so a refusal is safe to print, log or report.
 */
export function tryParseAccountId(text: string): CodecResult<string> {
  const trimmed = text.trim();
  if (trimmed.length === 0) {
    return codecFail("bad-argument", "the account is empty; it must be 17 to 19 digits", null, "account-empty");
  }
  if (!/^[0-9]+$/.test(trimmed)) {
    return codecFail(
      "bad-argument",
      `the account must be digits only (it is ${trimmed.length} characters, and at least one is not a digit)`,
      null,
      "account-non-digit",
    );
  }
  if (trimmed.length < ACCOUNT_ID_MIN_DIGITS || trimmed.length > ACCOUNT_ID_MAX_DIGITS) {
    return codecFail(
      "bad-argument",
      `the account must be ${ACCOUNT_ID_MIN_DIGITS} to ${ACCOUNT_ID_MAX_DIGITS} digits; this one is ${trimmed.length}`,
      null,
      "account-length",
    );
  }
  return codecOk(trimmed);
}

/** The packet an account frame would be, plus the plain statement that it needs the cipher. */
export interface AccountFramePlan {
  serviceId: number;
  commandId: number;
  request: HuaweiRequest;
  /** Upstream always encrypts this packet, so no plan is sendable as plaintext. */
  needsTransactionCipher: true;
  /** How many digits the value has. Never the value. */
  digits: number;
}

/**
 * Build the account packet. The value is validated first and only then encoded, so a malformed value
 * is refused before a frame exists. `command` defaults to 0x05, which is the one Gadgetbridge queues
 * (HuaweiSupportProvider.java:787); 0x01 is the legacy pair, kept because upstream still defines it.
 */
export function accountFramePlan(input: {
  account: string;
  command?: AccountCommand;
  pairingOptimization?: boolean;
}): CodecResult<AccountFramePlan> {
  const parsed = tryParseAccountId(input.account);
  if (!parsed.ok) return parsed;
  const request =
    (input.command ?? "send-extended") === "send"
      ? sendAccountRequest(parsed.value)
      : sendExtendedAccountRequest({
          account: parsed.value,
          accountPairingOptimization: input.pairingOptimization === true,
        });
  return codecOk({
    serviceId: request.serviceId,
    commandId: request.commandId,
    request,
    needsTransactionCipher: true,
    digits: parsed.value.length,
  });
}

/**
 * Encode a plan. Passing `transactionsCrypted: true` — the only form the watch accepts — always
 * returns the typed refusal below: the envelope is not part of this phase, and this helper will not
 * send an unencrypted account frame that the watch would reject. Passing `false` yields the plain
 * TLV frame, which is what the tests compare against upstream's pre-encryption layout.
 */
export function encodeAccountFrame(
  plan: AccountFramePlan,
  options: { sliceSize?: number; transactionsCrypted?: boolean } = {},
): CodecResult<Uint8Array[]> {
  if (options.transactionsCrypted !== false) {
    return codecFail(
      "unsupported",
      "an account frame must be encrypted with the transaction key (the 0x7C/0x7D/0x7E envelope, AES with the derived key); this helper sends plaintext auth frames only",
      null,
      "account-needs-cipher",
    );
  }
  return encodeRequest(plan.request, { sliceSize: options.sliceSize });
}
