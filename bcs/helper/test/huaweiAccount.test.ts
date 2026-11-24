// BCS helper — Phase 3E tests: the Huawei account ID rule and the frame upstream defines for it.
// Every value below is synthetic; no real account, key or device datum is used anywhere here.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// The rule asserted here is this project's, not upstream's: Gadgetbridge checks neither length nor
// digits (packets/AccountRelated.java:55-74 encodes whatever string it is given), while its own text
// field caps at 17 (res/xml/devicesettings_huawei_account.xml:6). We accept 17 to 19 digits.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  ACCOUNT_FRAME_PAIRS,
  ACCOUNT_ID_MAX_DIGITS,
  ACCOUNT_ID_MIN_DIGITS,
  accountFramePlan,
  encodeAccountFrame,
  isAccountId,
  tryParseAccountId,
} from "../src/huawei/account.ts";
import { ACCOUNT_RELATED } from "../src/huawei/constants.ts";
import { ALLOWED_REQUEST_IDS, isAllowedRequest } from "../src/huawei/requests.ts";
import { decodeFrames } from "../src/huawei/stream.ts";

const ok = <T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!result.ok) throw new Error("expected success");
  return result.value;
};

/** A synthetic account with exactly `length` digits (1, 2, 3, ... 0, 1, ...). */
const digits = (length: number): string => "1234567890".repeat(4).slice(0, length);
const SYNTHETIC = digits(17);

describe("account — what the helper accepts", () => {
  test("17, 18 and 19 digits are accepted; 16 and 20 are refused with the length only", () => {
    assert.equal(ACCOUNT_ID_MIN_DIGITS, 17);
    assert.equal(ACCOUNT_ID_MAX_DIGITS, 19);
    for (const length of [17, 18, 19]) {
      const value = digits(length);
      assert.equal(isAccountId(value), true, `length ${length}`);
      assert.equal(ok(tryParseAccountId(value)), value);
    }
    for (const length of [1, 15, 16, 20, 40]) {
      const value = digits(length);
      assert.equal(isAccountId(value), false, `length ${length}`);
      const refused = tryParseAccountId(value);
      assert.equal(refused.ok, false, `length ${length}`);
      if (refused.ok) throw new Error("unreachable");
      assert.equal(refused.error.code, "bad-argument");
      assert.equal(refused.error.detail, "account-length");
      assert.match(refused.error.message, new RegExp(`is ${length}$`));
    }
  });

  test("a non-digit is refused, and the refusal says so without echoing the value", () => {
    const value = `${digits(16)}x`;
    const refused = tryParseAccountId(value);
    assert.equal(refused.ok, false);
    if (refused.ok) throw new Error("unreachable");
    assert.equal(refused.error.detail, "account-non-digit");
    assert.match(refused.error.message, /digits only/);
    assert.equal(refused.error.message.includes(value), false);
    assert.equal(String(refused.error.detail).includes(value), false);
  });

  test("an empty value is refused, and surrounding whitespace is forgiven like upstream's trim", () => {
    const empty = tryParseAccountId("");
    assert.equal(empty.ok, false);
    if (empty.ok) throw new Error("unreachable");
    assert.equal(empty.error.detail, "account-empty");
    assert.equal(tryParseAccountId("   \n").ok, false);
    // SendExtendedAccountRequest.java:49 reads the preference with .trim(), so we trim too.
    assert.equal(ok(tryParseAccountId(`  ${SYNTHETIC}\n`)), SYNTHETIC);
  });
});

describe("account — the frame, and the cipher it still needs", () => {
  test("the default plan is the 0x1A/0x05 packet with the digits as UTF-8 under tag 0x01", () => {
    const plan = ok(accountFramePlan({ account: SYNTHETIC }));
    assert.equal(plan.serviceId, ACCOUNT_RELATED.serviceId);
    assert.equal(plan.commandId, ACCOUNT_RELATED.sendExtendedAccountToDevice);
    assert.equal(plan.needsTransactionCipher, true);
    assert.equal(plan.digits, SYNTHETIC.length);
    assert.deepEqual(plan.request.tlv.entries.map((entry) => entry.tag), [0x01]);
    assert.deepEqual(plan.request.tlv.getBytes(0x01), new TextEncoder().encode(SYNTHETIC));
    // AccountRelated.java:69-71 adds 0x03 only when the watch advertises the optimisation.
    const optimised = ok(accountFramePlan({ account: SYNTHETIC, pairingOptimization: true }));
    assert.deepEqual(optimised.request.tlv.getBytes(0x03), Uint8Array.of(0x01));
  });

  test("the legacy 0x1A/0x01 command is reachable and carries the same tag", () => {
    const plan = ok(accountFramePlan({ account: SYNTHETIC, command: "send" }));
    assert.equal(plan.commandId, ACCOUNT_RELATED.sendAccountToDevice);
    assert.deepEqual(plan.request.tlv.getBytes(0x01), new TextEncoder().encode(SYNTHETIC));
  });

  test("a malformed value never becomes a frame", () => {
    for (const bad of ["", "1234", `${digits(16)}z`, digits(20)]) {
      assert.equal(accountFramePlan({ account: bad }).ok, false, bad);
    }
  });

  test("encoding for the wire is refused with a typed account-needs-cipher error", () => {
    const plan = ok(accountFramePlan({ account: SYNTHETIC }));
    for (const options of [undefined, {}, { transactionsCrypted: true }]) {
      const refused = encodeAccountFrame(plan, options);
      assert.equal(refused.ok, false);
      if (refused.ok) throw new Error("unreachable");
      assert.equal(refused.error.code, "unsupported");
      assert.equal(refused.error.detail, "account-needs-cipher");
      // The refusal explains the envelope, and never carries the value or its bytes.
      assert.match(refused.error.message, /0x7C\/0x7D\/0x7E/);
      assert.equal(refused.error.message.includes(SYNTHETIC), false);
      assert.equal(new TextDecoder().decode(new TextEncoder().encode(refused.error.message)).includes(SYNTHETIC), false);
    }
  });

  test("the plaintext frame is the upstream layout: 0x1A, the command, and the digits in tag 0x01", () => {
    const plan = ok(accountFramePlan({ account: SYNTHETIC }));
    const frames = ok(encodeAccountFrame(plan, { transactionsCrypted: false }));
    assert.equal(frames.length, 1);
    const decoded = ok(decodeFrames(frames[0]));
    assert.equal(decoded.length, 1);
    assert.equal(decoded[0].serviceId, ACCOUNT_RELATED.serviceId);
    assert.equal(decoded[0].commandId, ACCOUNT_RELATED.sendExtendedAccountToDevice);
    assert.equal(decoded[0].tlv?.getString(0x01), SYNTHETIC);

    // A positive control for the leak checks below: the digits really are in the frame we would
    // send, so a search that finds nothing is a search that works.
    assert.equal(Buffer.from(frames[0]).includes(Buffer.from(SYNTHETIC, "utf8")), true);
  });

  test("both pairs are on the request allowlist, and the list matches the Python write gate", () => {
    assert.deepEqual(
      ACCOUNT_FRAME_PAIRS.map(([service, command]) => `${service}:${command}`),
      [`${ACCOUNT_RELATED.serviceId}:${ACCOUNT_RELATED.sendAccountToDevice}`,
       `${ACCOUNT_RELATED.serviceId}:${ACCOUNT_RELATED.sendExtendedAccountToDevice}`],
    );
    for (const [service, command] of ACCOUNT_FRAME_PAIRS) {
      assert.equal(isAllowedRequest(service, command), true, `${service}:${command}`);
      assert.equal(
        ALLOWED_REQUEST_IDS.some(([s, c]) => s === service && c === command),
        true,
        `${service}:${command}`,
      );
    }
    // A command upstream defines no packet for is still refused, so the allowlist is not a wildcard.
    assert.equal(isAllowedRequest(ACCOUNT_RELATED.serviceId, 0x06), false);
  });
});

describe("account — the value reaches nothing but the frame", () => {
  /** Every refusal this module can produce, with the account as input. */
  function refusalsFor(value: string): string[] {
    const lines: string[] = [];
    const parsed = tryParseAccountId(value);
    if (!parsed.ok) lines.push(parsed.error.message, String(parsed.error.detail));
    const planned = accountFramePlan({ account: value });
    if (!planned.ok) lines.push(planned.error.message, String(planned.error.detail));
    if (planned.ok) {
      const encoded = encodeAccountFrame(planned.value);
      if (!encoded.ok) lines.push(encoded.error.message, String(encoded.error.detail));
    }
    return lines;
  }

  test("no refusal string carries the value, valid or malformed", () => {
    for (const value of [SYNTHETIC, digits(19), `${digits(16)}x`, digits(16), ""]) {
      for (const line of refusalsFor(value)) {
        assert.equal(line.includes(value) && value.length > 0, false, `a refusal echoed ${value.length} digits`);
      }
    }
  });

  test("a refusal names the length, which is all a report needs", () => {
    const refused = tryParseAccountId(digits(16));
    assert.equal(refused.ok, false);
    if (refused.ok) throw new Error("unreachable");
    assert.match(refused.error.message, /is 16$/);
  });
});