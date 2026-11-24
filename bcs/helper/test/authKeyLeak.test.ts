// BCS helper — Phase 3 (trust/auth) tests: the promise that a key never leaks.
// Copyright (C) 2026 HyperionOS Project. SPDX-License-Identifier: AGPL-3.0-or-later
// See NOTICE in this directory for attribution and privacy rules.
//
// src/huawei/authErrors.ts states a hard rule: no key bytes, no key hex, no key base64 and nothing
// derived from the key may reach an error's `message` or `detail`, a log line, or the bytes the
// machine asks the caller to send. Every other test in this phase asserts *behaviour*; this one
// asserts that rule, by running the machine through every path it has — refusals, mismatches,
// truncation, disorder and one full success — with a distinctive synthetic key, and then searching
// everything the machine produced for that key in every spelling.
//
// The key here is synthetic and thrown away: 32 bytes chosen to be unmistakable in a search. No real
// key, no watch, no radio, no health data, and nothing is ever sent anywhere.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { createAuthMachine, type AuthMachine } from "../src/huawei/authMachine.ts";
import { DEVICE_CONFIG } from "../src/huawei/constants.ts";
import { hexToBytes, hexdumpUpper, hmacSha256 } from "../src/huawei/crypto.ts";
import type { HuaweiFrame } from "../src/huawei/frame.ts";
import { decodeFrames } from "../src/huawei/stream.ts";
import { HuaweiTlv } from "../src/huawei/tlv.ts";

type Result<T> =
  | { ok: true; value: T }
  | { ok: false; error: { code: string; message: string; detail: string | null } };

const ok = <T>(result: Result<T>): T => {
  if (!result.ok) throw new Error(`expected success, got ${result.error.code}: ${result.error.message}`);
  return result.value;
};
const hex = (text: string): Uint8Array => ok(hexToBytes(text));
const bytes = (...values: number[]): Uint8Array => Uint8Array.from(values);

/** The key under test: 32 bytes, and a spelling no other string in a transcript can contain. */
const LEAK_KEY = hex("c3f1a7d29b4e6f8013579bdf2468ace0c3f1a7d29b4e6f8013579bdf2468ace0");
/** selfAuthId: 32 UTF-8 characters, the shape upstream's getAndroidId() produces. */
const ANDROID_ID = new Uint8Array(Buffer.from("0123456789abcdef0123456789abcdef", "utf8"));

/** Every spelling of a secret that a careless message could carry. */
function spellings(secret: Uint8Array): string[] {
  const upper = hexdumpUpper(secret);
  const base64 = Buffer.from(secret).toString("base64");
  return [upper, upper.toLowerCase(), base64, base64.replace(/=+$/, ""), Buffer.from(secret).toString("hex")];
}

/** Does this byte string contain `needle` anywhere? */
function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0 || haystack.length < needle.length) return false;
  outer: for (let start = 0; start <= haystack.length - needle.length; start += 1) {
    for (let index = 0; index < needle.length; index += 1) {
      if (haystack[start + index] !== needle[index]) continue outer;
    }
    return true;
  }
  return false;
}

const concatBytes = (parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

const reply = (commandId: number, tlv: HuaweiTlv | null): HuaweiFrame => ({
  serviceId: DEVICE_CONFIG.serviceId,
  commandId,
  tlv,
  payload: new Uint8Array(0),
  encryptedEnvelope: false,
  sliceType: 0,
  sliceFlags: [],
  sliceCount: 1,
});

/** A LinkParams reply, with the tags that decide the auth path. */
function linkParamsTlv(deviceSupportType = 0x04): HuaweiTlv {
  return new HuaweiTlv()
    .putByte(0x01, 0x02)
    .putShort(0x02, 0x00f4)
    .putBytes(0x05, bytes(0x00, 0x02, ...new Array(16).fill(0x11)))
    .putByte(0x07, deviceSupportType)
    .putByte(0x08, 0x00)
    .putByte(0x0c, 0x00);
}

const statusTlv = (status: number): HuaweiTlv => new HuaweiTlv().putByte(0x01, status);
const negotiationTlv = (value = 0x01): HuaweiTlv => new HuaweiTlv().putByte(0x01, value);
const hiChainJson = (payload: Record<string, unknown>): HuaweiTlv =>
  new HuaweiTlv().putByte(0x04, 0x00).putString(0x01, JSON.stringify({ payload }));
const hiChainStep4 = (): HuaweiTlv =>
  new HuaweiTlv().putByte(0x04, 0x01).putString(0x01, "ok");

/** What the caller would have to send, decoded back into the HiChain envelope it built. */
function hiChainEnvelopeOf(out: Uint8Array[]): Record<string, unknown> {
  const frames = ok(decodeFrames(concatBytes(out)));
  const text = ok(frames[0].tlv!.tryGetString(0x01));
  return JSON.parse(text) as Record<string, unknown>;
}

/** A deterministic machine: fixed RNG, fixed request id, so a leak would be reproducible. */
function machineWith(input: { key?: Uint8Array; mode?: "bind" | "auth-then-bind"; pinCode?: Uint8Array } = {}) {
  return createAuthMachine({
    key: input.key ?? LEAK_KEY,
    androidId: ANDROID_ID,
    mode: input.mode,
    pinCode: input.pinCode ?? null,
    random: (n: number) => Uint8Array.from({ length: n }, (_, index) => 0x40 + index),
    requestId: () => 42n,
  });
}

/** What the machine produced, in the form a caller would report or log it. */
interface Transcript {
  /** Every error, rendered as it would reach a user or a log. */
  errors: string[];
  /** Every byte string the machine asked the caller to send. */
  sent: Uint8Array[];
}

function record(transcript: Transcript, result: Result<{ out: Uint8Array[] }>, label: string): void {
  if (result.ok) {
    transcript.sent.push(...result.value.out);
    return;
  }
  const { code, message, detail } = result.error;
  // The rendered form and the JSON of the error object, so a field added later is caught too.
  transcript.errors.push(`${label} | ${code} | ${message} | ${detail ?? ""} | ${JSON.stringify(result.error)}`);
}

/** The watch's half of step 1, with a token over the *verified* order. */
const WATCH_SALT = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
const WATCH_AUTH_ID = new Uint8Array(Buffer.from("fedcba9876543210fedcba9876543210", "utf8"));

function step1Reply(psk: Uint8Array, randSelf: Uint8Array): HuaweiTlv {
  const token = hmacSha256(psk, concatBytes([WATCH_SALT, randSelf, ANDROID_ID, WATCH_AUTH_ID]));
  return hiChainJson({
    isoSalt: hexdumpUpper(WATCH_SALT),
    peerAuthId: hexdumpUpper(WATCH_AUTH_ID),
    peerUserType: 0,
    token: hexdumpUpper(token),
  });
}

/** Walk to the first HiChain step, recording everything, and report the two values it generated. */
function walkToBindStep1(
  machine: AuthMachine,
  transcript: Transcript,
  label: string,
): { randSelf: Uint8Array; seed: Uint8Array } | null {
  record(transcript, machine.start(), `${label}:start`);
  record(transcript, machine.onFrame(reply(DEVICE_CONFIG.linkParams, linkParamsTlv())), `${label}:link-params`);
  record(transcript, machine.onFrame(reply(DEVICE_CONFIG.deviceStatus, statusTlv(0x01))), `${label}:device-status`);
  const negotiation = machine.onFrame(reply(DEVICE_CONFIG.securityNegotiation, negotiationTlv()));
  record(transcript, negotiation, `${label}:negotiation`);
  if (!negotiation.ok) return null;
  const payload = hiChainEnvelopeOf(negotiation.value.out).payload as { isoSalt: string; seed: string };
  return { randSelf: hex(payload.isoSalt), seed: hex(payload.seed) };
}

/**
 * Every path the machine has, run once. Refusals, framing errors, a wrong key, a tampered MAC, a
 * replayed step, a truncated step, an unsupported device, a missing key, a bad pin code reply — and
 * one full success, whose derived key then joins the search.
 */
function runEveryPath(): { transcript: Transcript; finalKey: Uint8Array | null } {
  const transcript: Transcript = { errors: [], sent: [] };

  // 1. A machine with no key at all: refused at the security negotiation, before anything is built.
  walkToBindStep1(machineWith({ key: new Uint8Array(0) }), transcript, "no-key");

  // 2. Framing: no TLV, and a frame from a state that does not expect it.
  {
    const machine = machineWith();
    record(transcript, machine.start(), "framing:start");
    record(transcript, machine.onFrame(reply(DEVICE_CONFIG.linkParams, null)), "framing:no-tlv");
    const other = machineWith();
    record(transcript, other.start(), "framing:start2");
    record(transcript, other.onFrame(reply(DEVICE_CONFIG.hiChain, hiChainJson({}))), "framing:wrong-id");
  }

  // 3. A watch that has no HiChain, and one that reports a status that skips authentication.
  {
    const machine = machineWith();
    record(transcript, machine.start(), "no-hichain:start");
    record(transcript, machine.onFrame(reply(DEVICE_CONFIG.linkParams, linkParamsTlv(0x02))), "no-hichain:link");
    const status = machineWith();
    record(transcript, status.start(), "status:start");
    record(transcript, status.onFrame(reply(DEVICE_CONFIG.linkParams, linkParamsTlv())), "status:link");
    record(transcript, status.onFrame(reply(DEVICE_CONFIG.deviceStatus, statusTlv(0x07))), "status:refused");
  }

  // 4. A watch that negotiated HiChainLite (authType 0) instead of HiChain.
  {
    const machine = machineWith();
    record(transcript, machine.start(), "lite:start");
    record(transcript, machine.onFrame(reply(DEVICE_CONFIG.linkParams, linkParamsTlv())), "lite:link");
    record(transcript, machine.onFrame(reply(DEVICE_CONFIG.deviceStatus, statusTlv(0x01))), "lite:status");
    record(transcript, machine.onFrame(reply(DEVICE_CONFIG.securityNegotiation, new HuaweiTlv().putByte(0x02, 0x00))),
      "lite:negotiation");
  }

  // 5. The wrong key: the watch's step-1 token does not match. The likeliest place for a leak.
  {
    const machine = machineWith();
    const state = walkToBindStep1(machine, transcript, "wrong-key");
    if (state) {
      const wrongPsk = hmacSha256(hex("00".repeat(32)), state.seed);
      record(transcript, machine.onFrame(reply(DEVICE_CONFIG.hiChain, step1Reply(wrongPsk, state.randSelf))),
        "wrong-key:step1");
    }
  }

  // 6. A tampered return-code MAC at step 2: the other place with two secrets to compare.
  {
    const machine = machineWith();
    const state = walkToBindStep1(machine, transcript, "mac");
    if (state) {
      const psk = hmacSha256(LEAK_KEY, state.seed);
      record(transcript, machine.onFrame(reply(DEVICE_CONFIG.hiChain, step1Reply(psk, state.randSelf))), "mac:step1");
      record(transcript, machine.onFrame(reply(DEVICE_CONFIG.hiChain, hiChainJson({
        returnCodeMac: hexdumpUpper(hex("11".repeat(32))),
      }))), "mac:step2");
    }
  }

  // 7. Disorder, a refusal and a truncation, each on a machine that got to step 1 honestly.
  {
    const outOfOrder = machineWith();
    if (walkToBindStep1(outOfOrder, transcript, "order")) {
      record(transcript, outOfOrder.onFrame(reply(DEVICE_CONFIG.hiChain, hiChainJson({
        returnCodeMac: hexdumpUpper(hex("22".repeat(32))),
      }))), "order:step2");
    }
    const refusal = machineWith();
    if (walkToBindStep1(refusal, transcript, "error-code")) {
      record(transcript, refusal.onFrame(reply(DEVICE_CONFIG.hiChain, hiChainJson({ errorCode: 9 }))),
        "error-code:step1");
    }
    const truncated = machineWith();
    if (walkToBindStep1(truncated, transcript, "truncated")) {
      record(transcript, truncated.onFrame(reply(DEVICE_CONFIG.hiChain, hiChainJson({
        isoSalt: hexdumpUpper(WATCH_SALT),
      }))), "truncated:step1");
    }
  }

  // 8. The pin-code path, with a reply this machine cannot open. The AES key there is the *static*
  //    digest secret, never the user's key, and the error must not name either.
  {
    const machine = machineWith({ mode: "auth-then-bind" });
    record(transcript, machine.start(), "pin:start");
    record(transcript, machine.onFrame(reply(DEVICE_CONFIG.linkParams, linkParamsTlv())), "pin:link");
    record(transcript, machine.onFrame(reply(DEVICE_CONFIG.deviceStatus, statusTlv(0x01))), "pin:status");
    record(transcript, machine.onFrame(reply(DEVICE_CONFIG.securityNegotiation, negotiationTlv())), "pin:negotiation");
    record(transcript, machine.onFrame(reply(DEVICE_CONFIG.pinCode, new HuaweiTlv()
      .putBytes(0x01, bytes(...new Array(16).fill(0x33)))
      .putBytes(0x02, bytes(...new Array(16).fill(0x44))))), "pin:reply");
  }

  // 9. The full bind flow, so the derived key is in hand for the search as well.
  let finalKey: Uint8Array | null = null;
  {
    const machine = machineWith();
    const state = walkToBindStep1(machine, transcript, "success");
    if (state) {
      const psk = hmacSha256(LEAK_KEY, state.seed);
      record(transcript, machine.onFrame(reply(DEVICE_CONFIG.hiChain, step1Reply(psk, state.randSelf))),
        "success:step1");
      record(transcript, machine.onFrame(reply(DEVICE_CONFIG.hiChain, hiChainJson({
        returnCodeMac: hexdumpUpper(hmacSha256(psk, Uint8Array.of(0, 0, 0, 0))),
      }))), "success:step2");
      record(transcript, machine.onFrame(reply(DEVICE_CONFIG.hiChain, hiChainStep4())), "success:step4");
      finalKey = machine.finalKey ? Uint8Array.from(machine.finalKey) : null;
    }
  }
  return { transcript, finalKey };
}

describe("authKeyLeak — the key never reaches an error, a log line or the wire", () => {
  test("the detectors themselves work, so a clean run cannot be vacuous", () => {
    const leak = `token=${hexdumpUpper(LEAK_KEY)}`;
    assert.equal(spellings(LEAK_KEY).some((form) => leak.includes(form)), true);
    const base64Leak = `key=${Buffer.from(LEAK_KEY).toString("base64")}`;
    assert.equal(spellings(LEAK_KEY).some((form) => base64Leak.includes(form)), true);
    assert.equal(containsBytes(concatBytes([bytes(0x5a, 0x00), LEAK_KEY]), LEAK_KEY), true);
    assert.equal(containsBytes(bytes(1, 2, 3), LEAK_KEY), false);
  });

  test("every failure path, the success path and the console: nothing carries the key", () => {
    // The machine must not log either. Capture the console for the duration of the runs.
    const calls: string[] = [];
    const saved = { log: console.log, warn: console.warn, error: console.error, info: console.info };
    const capture = (name: string) => (...args: unknown[]) => {
      calls.push(`${name} ${args.map((arg) => String(arg)).join(" ")}`);
    };
    console.log = capture("log");
    console.warn = capture("warn");
    console.error = capture("error");
    console.info = capture("info");
    let run: { transcript: Transcript; finalKey: Uint8Array | null };
    try {
      run = runEveryPath();
    } finally {
      console.log = saved.log;
      console.warn = saved.warn;
      console.error = saved.error;
      console.info = saved.info;
    }

    // The scenarios must actually have failed, or the search below proves nothing.
    assert.ok(run.transcript.errors.length >= 10, `recorded ${run.transcript.errors.length} errors, wanted 10+`);
    assert.ok(run.transcript.sent.length >= 4, `recorded ${run.transcript.sent.length} requests, wanted 4+`);
    assert.equal(calls.length, 0, "the auth machine must never write to the console");

    // 1. No error message, detail or rendered error carries the key or the derived key in any spelling.
    const secrets = run.finalKey ? [LEAK_KEY, run.finalKey] : [LEAK_KEY];
    for (const error of run.transcript.errors) {
      for (const secret of secrets) {
        for (const form of spellings(secret)) {
          assert.equal(error.includes(form), false, `an error carried a key in this form: ${error}`);
        }
      }
    }

    // 2. Nothing the machine asked the caller to send carries the key, as bytes or as text.
    const decoder = new TextDecoder();
    for (const request of run.transcript.sent) {
      assert.equal(containsBytes(request, LEAK_KEY), false, "a request carried the raw key");
      const text = decoder.decode(request);
      for (const form of spellings(LEAK_KEY)) {
        assert.equal(text.includes(form), false, "a request carried the key as text");
      }
    }

    // 3. The derived key exists, differs from the auth key, and never went on the wire either.
    assert.ok(run.finalKey, "the success path must produce a key");
    assert.notDeepEqual(run.finalKey, LEAK_KEY);
    for (const request of run.transcript.sent) {
      assert.equal(containsBytes(request, run.finalKey), false, "a request carried the derived key");
    }
  });
});